import { randomUUID } from "node:crypto";
import { PrismaPg } from "@prisma/adapter-pg";
import { Prisma, PrismaClient } from "./generated/prisma/client.js";
import { AuthorizationChangedError, EmailInUseError, type ProductDraft, type Repository, type User } from "./repository.js";
import type { OAuthAttemptStore } from "./stripe/oauth-sandbox.js";
import type { LiveOAuthStore } from "./stripe/oauth-live.js";
import type { SecretVersion } from "./secrets/secret-manager.js";
import type { OAuthRotationStore, RotationClaim } from "./stripe/oauth-token-rotation.js";
import type { PublicationStore } from "./stripe/publication-store.js";
import type { CheckoutStore, CheckoutStorefront } from "./stripe/checkout-store.js";
import type { CheckoutWebhookStore } from "./stripe/checkout-webhook.js";
import type { CheckoutObservation, CheckoutReconciliationStore } from "./stripe/checkout-reconciliation-store.js";
import type { CheckoutEventWorkStore } from "./stripe/checkout-event-worker.js";
import type { CheckoutRecoveryWorkStore } from "./stripe/checkout-recovery-worker.js";
import type { CheckoutRecoveryBindingStore } from "./stripe/checkout-recovery-runtime.js";
import { hasStorefrontDnsProof, parseStorefrontProposal, storefrontSetupSchema, type StorefrontProposalStore } from "./stripe/storefront-proposal.js";
import { PostgresRateLimitStore } from "./postgres-rate-limit-store.js";

export function createDatabase(databaseUrl: string, resolveStorefrontTxt?: (name: string) => Promise<string[][]>) {
  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: databaseUrl }) });
  const loginRateLimitStore = new PostgresRateLimitStore(prisma);
  const authorizedBusiness = (user: User) => Prisma.sql`
    EXISTS (
      SELECT 1 FROM "User" u WHERE u."id" = ${user.id} AND u."sessionVersion" = ${user.sessionVersion} AND (
        u."role" = 'ADMIN' OR EXISTS (
          SELECT 1 FROM "Membership" m
          WHERE m."userId" = u."id" AND m."businessId" = b."id" AND m."role" = 'OWNER'
        )
      )
    )`;
  const lockActiveActor = async (tx: Prisma.TransactionClient, user: User) => {
    const rows = await tx.$queryRaw<{ id: string; role: "ADMIN" | "USER" }[]>`
      SELECT "id", "role" FROM "User"
      WHERE "id" = ${user.id} AND "sessionVersion" = ${user.sessionVersion}
      FOR UPDATE`;
    if (!rows[0]) throw new AuthorizationChangedError();
    return rows[0];
  };
  const repository: Repository = {
    checkHealth: async () => {
      await prisma.$queryRaw`
        SELECT u."sessionVersion", s."sid", l."totalHits", a."action", p."amountCents", r."payload", t."usedAt",
          m."lastTimeStep", c."codeHash", k."fingerprint", g."expiresAt", sp."status",
          co."publicationId", co."initialPaymentStatus", ca."status", ce."sessionId", cr."observedStatus", cw."status",
          sf."revision", sf."verifiedAt", sf."testApprovedAt", co."storefrontRevision", co."storefrontRequestId", rw."status", sc."connectProvisionedAt"
        FROM "User" u, "session" s, "LoginRateLimit" l, "AuditEvent" a, "ProductDraft" p,
          "PasswordResetDelivery" r, "PasswordResetToken" t, "MfaAuthenticator" m, "MfaBackupCode" c, "MfaKeyState" k,
          "MfaRecoveryGrant" g, "StripePublication" sp, "CheckoutOrder" co, "CheckoutAttempt" ca,
          "StripeCheckoutEvent" ce, "StripeCheckoutEventResult" cr, "StripeCheckoutEventWork" cw,
          "StorefrontProposal" sf, "CheckoutRecoveryWork" rw, "StripeConnection" sc
        LIMIT 0`;
    },
    findUserByEmail: (email) => prisma.user.findUnique({ where: { email } }),
    findUserById: (id) => prisma.user.findUnique({ where: { id } }),
    hasMfaAuthenticator: async (id) => !!await prisma.mfaAuthenticator.findUnique({
      where: { userId: id }, select: { userId: true }
    }),
    recordLoginAttempt: async (userId, succeeded) => {
      await prisma.auditEvent.create({
        data: { actorId: userId, targetId: userId, action: succeeded ? "LOGIN_SUCCEEDED" : "LOGIN_FAILED" }
      });
    },
    upgradePasswordHash: async (id, previousHash, newHash) => {
      const result = await prisma.user.updateMany({
        where: { id, passwordHash: previousHash },
        data: { passwordHash: newHash }
      });
      return result.count === 1;
    },
    changePassword: (id, previousHash, newHash) => prisma.$transaction(async (tx) => {
      const result = await tx.user.updateMany({
        where: { id, passwordHash: previousHash },
        data: { passwordHash: newHash, sessionVersion: { increment: 1 } }
      });
      if (result.count === 1) {
        await tx.auditEvent.create({ data: { actorId: id, action: "PASSWORD_CHANGED", targetId: id } });
      }
      return result.count === 1;
    }),
    listBusinesses: (user) => prisma.business.findMany({
      where: user.role === "ADMIN" ? {} : { memberships: { some: { userId: user.id } } },
      select: { id: true, name: true },
      orderBy: { name: "asc" }
    }),
    findBusiness: (user, id) => prisma.business.findFirst({
      where: { id, ...(user.role === "ADMIN" ? {} : { memberships: { some: { userId: user.id } } }) },
      select: { id: true, name: true }
    }),
    findVerifiedTestCredential: async (user, businessId) => {
      const connection = await prisma.stripeConnection.findFirst({
        where: {
          businessId, mode: "TEST", status: "VERIFIED",
          business: user.role === "ADMIN" ? {} : { memberships: { some: { userId: user.id, role: "OWNER" } } }
        },
        select: { credential: { select: { secretId: true, version: true } } }
      });
      return connection?.credential ?? null;
    },
    createBusinessWithOwner: (actor, name, email, passwordHash) => prisma.$transaction(async (tx) => {
      const administrators = await tx.$queryRaw<{ id: string }[]>`
        SELECT "id" FROM "User"
        WHERE "id" = ${actor.id} AND "role" = 'ADMIN' AND "sessionVersion" = ${actor.sessionVersion}
        FOR UPDATE`;
      if (!administrators[0]) throw new AuthorizationChangedError();
      const owners = await tx.$queryRaw<{ id: string }[]>`
        INSERT INTO "User" ("id", "email", "passwordHash")
        VALUES (${randomUUID()}, ${email}, ${passwordHash})
        ON CONFLICT ("email") DO NOTHING
        RETURNING "id"`;
      const owner = owners[0];
      if (!owner) throw new EmailInUseError();
      const business = await tx.business.create({
        data: { name, memberships: { create: { userId: owner.id } } },
        select: { id: true, name: true }
      });
      await tx.auditEvent.create({
        data: { actorId: actor.id, action: "BUSINESS_CREATED", targetId: owner.id, businessId: business.id }
      });
      return business;
    }),
    listProductDrafts: (user, businessId) => prisma.$queryRaw<ProductDraft[]>`
      SELECT p.* FROM "ProductDraft" p
      JOIN "Business" b ON b."id" = p."businessId"
      WHERE b."id" = ${businessId} AND ${authorizedBusiness(user)}
      ORDER BY p."createdAt" DESC, p."id" DESC`,
    createProductDraft: (user, businessId, draft) => prisma.$transaction(async (tx) => {
      await lockActiveActor(tx, user);
      const rows = await tx.$queryRaw<ProductDraft[]>`
        INSERT INTO "ProductDraft"
          ("id", "businessId", "name", "description", "kind", "amountCents", "billing", "interval", "updatedAt")
        SELECT ${randomUUID()}, b."id", ${draft.name}, ${draft.description}, ${draft.kind},
          ${draft.amountCents}, ${draft.billing}, ${draft.interval}, CURRENT_TIMESTAMP
        FROM "Business" b WHERE b."id" = ${businessId} AND ${authorizedBusiness(user)}
        RETURNING *`;
      if (rows[0]) {
        await tx.auditEvent.create({
          data: { actorId: user.id, action: "PRODUCT_DRAFT_CREATED", targetId: rows[0].id, businessId }
        });
      }
      return rows[0] ?? null;
    }),
    updateProductDraft: (user, businessId, id, draft) => prisma.$transaction(async (tx) => {
      await lockActiveActor(tx, user);
      const rows = await tx.$queryRaw<ProductDraft[]>`
        UPDATE "ProductDraft" p SET "name" = ${draft.name}, "description" = ${draft.description},
          "kind" = ${draft.kind}, "amountCents" = ${draft.amountCents}, "billing" = ${draft.billing},
          "interval" = ${draft.interval}, "updatedAt" = CURRENT_TIMESTAMP
        FROM "Business" b
        WHERE p."id" = ${id} AND p."businessId" = b."id" AND b."id" = ${businessId}
          AND ${authorizedBusiness(user)}
        RETURNING p.*`;
      if (rows[0]) {
        await tx.auditEvent.create({
          data: { actorId: user.id, action: "PRODUCT_DRAFT_UPDATED", targetId: rows[0].id, businessId }
        });
      }
      return rows[0] ?? null;
    })
  };
  const lockStorefrontAccess = async (tx: Prisma.TransactionClient, actor: User, businessId: string) => {
    const activeActor = await lockActiveActor(tx, actor);
    const businesses = await tx.$queryRaw<{ id: string }[]>`
      SELECT "id" FROM "Business" WHERE "id" = ${businessId} FOR KEY SHARE`;
    if (!businesses[0]) return false;
    if (activeActor.role === "ADMIN") return true;
    const memberships = await tx.$queryRaw<{ userId: string }[]>`
      SELECT "userId" FROM "Membership"
      WHERE "userId" = ${actor.id} AND "businessId" = ${businessId} AND "role" = 'OWNER'
      FOR SHARE`;
    return memberships.length > 0;
  };
  const storefrontProposal: StorefrontProposalStore = {
    find: async (actor, businessId) => {
      const rows = await prisma.$queryRaw<import("./generated/prisma/client.js").StorefrontProposal[]>`
        SELECT s.* FROM "StorefrontProposal" s
        JOIN "Business" b ON b."id" = s."businessId"
        WHERE b."id" = ${businessId} AND ${authorizedBusiness(actor)}`;
      return rows[0] ?? null;
    },
    save: async (actor, businessId, input) => {
      const proposal = parseStorefrontProposal(input);
      return prisma.$transaction(async (tx) => {
        if (!await lockStorefrontAccess(tx, actor, businessId)) return null;
        const revision = randomUUID();
        const saved = await tx.storefrontProposal.upsert({
          where: { businessId },
          create: { businessId, ...proposal, revision },
          update: { ...proposal, revision, verifiedAt: null, testApprovedAt: null }
        });
        await tx.auditEvent.create({
          data: { actorId: actor.id, action: "STOREFRONT_PROPOSED", targetId: businessId, businessId }
        });
        return saved;
      });
    },
    approveTest: (actor, businessId, revision) => prisma.$transaction(async (tx) => {
      if ((await lockActiveActor(tx, actor)).role !== "ADMIN") return null;
      const proposal = await tx.storefrontProposal.findUnique({ where: { businessId } });
      if (!proposal || proposal.revision !== revision ||
          !storefrontSetupSchema.safeParse({ origin: proposal.origin, returnUrl: proposal.returnUrl }).success) return null;
      const [approved] = await tx.storefrontProposal.updateManyAndReturn({
        where: { businessId, revision, testApprovedAt: null },
        data: { testApprovedAt: new Date() }
      });
      if (!approved) return tx.storefrontProposal.findFirst({
        where: { businessId, revision, testApprovedAt: { not: null } }
      });
      await tx.auditEvent.create({
        data: { actorId: actor.id, action: "STOREFRONT_TEST_APPROVED", targetId: revision, businessId }
      });
      return approved;
    }),
    verify: async (actor, businessId, revision) => {
      const proposal = await storefrontProposal.find(actor, businessId);
      if (!proposal || proposal.revision !== revision ||
          !await hasStorefrontDnsProof(proposal, resolveStorefrontTxt)) return null;
      const verifiedAt = new Date();
      return prisma.$transaction(async (tx) => {
        if (!await lockStorefrontAccess(tx, actor, businessId)) return null;
        const [verified] = await tx.storefrontProposal.updateManyAndReturn({
          where: { businessId, revision, OR: [{ verifiedAt: null }, { verifiedAt: { lte: verifiedAt } }] },
          data: { verifiedAt }
        });
        if (!verified) return null;
        await tx.auditEvent.create({
          data: { actorId: actor.id, action: "STOREFRONT_DNS_VERIFIED", targetId: revision, businessId }
        });
        return verified;
      });
    }
  };
  const sandboxOAuthBinding = {
    status: async (user: User, businessId: string) => {
      const [connection] = await prisma.$queryRaw<{ status: string; oauthStatus: string | null }[]>`
        SELECT c."status", o."status" AS "oauthStatus" FROM "StripeConnection" c
        JOIN "Business" b ON b."id" = c."businessId"
        LEFT JOIN "StripeOAuthCredential" o ON o."connectionId" = c."id"
        WHERE b."id" = ${businessId} AND c."mode" = 'TEST' AND ${authorizedBusiness(user)}`;
      if (!connection) return "available" as const;
      return connection.status === "VERIFIED" && connection.oauthStatus === "READY"
        ? "connected" as const : "unavailable" as const;
    },
    reserve: (actor: User, businessId: string, accountId: string) => prisma.$transaction(async (tx) => {
      if (!await lockStorefrontAccess(tx, actor, businessId)) return null;
      const [connection] = await tx.$queryRaw<{ id: string }[]>`
        INSERT INTO "StripeConnection" ("id", "businessId", "mode", "stripeAccountId", "updatedAt")
        VALUES (${randomUUID()}, ${businessId}, 'TEST', ${accountId}, CURRENT_TIMESTAMP)
        ON CONFLICT DO NOTHING RETURNING "id"`;
      if (!connection) return null;
      await tx.auditEvent.create({
        data: { actorId: actor.id, businessId, targetId: connection.id, action: "STRIPE_SANDBOX_OAUTH_RESERVED" }
      });
      return connection.id;
    }),
    complete: (actor: User, businessId: string, connectionId: string, accountId: string,
      reference: { secretId: string; version: string }) => prisma.$transaction(async (tx) => {
      if (!await lockStorefrontAccess(tx, actor, businessId)) return false;
      const result = await tx.stripeConnection.updateMany({
        where: { id: connectionId, businessId, stripeAccountId: accountId, mode: "TEST", status: "PENDING_VERIFICATION" },
        data: { status: "VERIFIED" }
      });
      if (result.count !== 1) return false;
      await tx.stripeOAuthCredential.create({ data: { connectionId, ...reference } });
      await tx.auditEvent.create({
        data: { actorId: actor.id, businessId, targetId: connectionId, action: "STRIPE_SANDBOX_OAUTH_CONNECTED" }
      });
      return true;
    })
  };
  const oauthAttempts: OAuthAttemptStore = {
    create: (attempt) => prisma.$transaction(async (tx) => {
      await tx.stripeOAuthAttempt.updateMany({
        where: { businessId: attempt.businessId, environment: "SANDBOX", active: true, expiresAt: { lte: new Date() } },
        data: { active: false }
      });
      const rows = await tx.$executeRaw`
        INSERT INTO "StripeOAuthAttempt" ("id", "stateHash", "sessionHash", "userId", "businessId", "environment", "expiresAt")
        SELECT ${attempt.id}, ${attempt.stateHash}, ${attempt.sessionHash}, u."id", b."id", 'SANDBOX', ${attempt.expiresAt}
        FROM "User" u CROSS JOIN "Business" b
        WHERE u."id" = ${attempt.userId} AND b."id" = ${attempt.businessId}
          AND (u."role" = 'ADMIN' OR EXISTS (
            SELECT 1 FROM "Membership" m WHERE m."userId" = u."id" AND m."businessId" = b."id" AND m."role" = 'OWNER'
          ))
        ON CONFLICT DO NOTHING`;
      return rows === 1;
    }),
    consume: async (stateHash, sessionHash, userId, now, businessId) => {
      const rows = await prisma.$executeRaw`
        UPDATE "StripeOAuthAttempt" a SET "active" = false
        WHERE a."stateHash" = ${stateHash} AND a."sessionHash" = ${sessionHash}
          AND a."userId" = ${userId} AND a."environment" = 'SANDBOX'
          AND (${businessId ?? null}::text IS NULL OR a."businessId" = ${businessId ?? null})
          AND a."active" = true AND a."expiresAt" > ${now}
          AND EXISTS (
            SELECT 1 FROM "User" u WHERE u."id" = a."userId" AND (
              u."role" = 'ADMIN' OR EXISTS (
                SELECT 1 FROM "Membership" m WHERE m."userId" = u."id"
                  AND m."businessId" = a."businessId" AND m."role" = 'OWNER'
              )
            )
          )`;
      return rows === 1;
    }
  };
  const liveOAuthState: Omit<LiveOAuthStore, "bind"> = {
    create: (attempt) => prisma.$transaction(async (tx) => {
      await tx.stripeOAuthAttempt.updateMany({ where: {
        businessId: attempt.businessId, environment: "LIVE", active: true, expiresAt: { lte: new Date() }
      }, data: { active: false } });
      return await tx.$executeRaw`
        INSERT INTO "StripeOAuthAttempt" ("id", "stateHash", "sessionHash", "userId", "businessId", "environment", "expiresAt")
        SELECT ${attempt.id}, ${attempt.stateHash}, ${attempt.sessionHash}, m."userId", m."businessId", 'LIVE', ${attempt.expiresAt}
        FROM "Membership" m JOIN "User" u ON u."id" = m."userId"
        WHERE m."businessId" = ${attempt.businessId} AND m."userId" = ${attempt.userId}
          AND m."role" = 'OWNER' AND u."role" = 'USER'
        ON CONFLICT DO NOTHING` === 1;
    }),
    consume: async (stateHash, sessionHash, actor) => {
      const [row] = await prisma.$queryRaw<{ businessId: string }[]>`
        UPDATE "StripeOAuthAttempt" a SET "active" = false
        WHERE a."stateHash" = ${stateHash} AND a."sessionHash" = ${sessionHash}
          AND a."userId" = ${actor.id} AND a."environment" = 'LIVE'
          AND a."active" = true AND a."expiresAt" > CURRENT_TIMESTAMP
          AND EXISTS (SELECT 1 FROM "Membership" m JOIN "User" u ON u."id" = m."userId"
            WHERE m."userId" = a."userId" AND m."businessId" = a."businessId" AND m."role" = 'OWNER'
              AND u."role" = 'USER' AND u."sessionVersion" = ${actor.sessionVersion})
        RETURNING a."businessId"`;
      return row?.businessId;
    },
    status: async (actor, businessId) => {
      if (actor.role !== "USER" || !await repository.findBusiness(actor, businessId)) return "unavailable";
      const connection = await prisma.stripeConnection.findUnique({
        where: { businessId_mode: { businessId, mode: "LIVE" } },
        select: { status: true, oauthCredential: { select: { status: true } } }
      });
      if (!connection) return "available";
      if (connection.status !== "VERIFIED") return "unavailable";
      if (connection.oauthCredential?.status === "READY") return "connected";
      return connection.oauthCredential?.status === "RECONNECT_REQUIRED" ? "reconnect_required" : "unavailable";
    }
  };
  const bindLiveOAuth = (actor: User, businessId: string, accountId: string, reference: SecretVersion) =>
    prisma.$transaction(async (tx) => {
      if (actor.role !== "USER" || !await lockStorefrontAccess(tx, actor, businessId)) return false;
      const existing = await tx.stripeConnection.findUnique({
        where: { businessId_mode: { businessId, mode: "LIVE" } },
        select: { id: true, status: true, stripeAccountId: true }
      });
      if (existing) {
        if (existing.status !== "VERIFIED" || existing.stripeAccountId !== accountId) return false;
        const replaced = await tx.stripeOAuthCredential.updateMany({
          where: { connectionId: existing.id, status: "RECONNECT_REQUIRED", secretId: reference.secretId,
            version: { not: reference.version },
            connection: { businessId, mode: "LIVE", status: "VERIFIED", stripeAccountId: accountId } },
          data: { version: reference.version, status: "READY", operationId: null }
        });
        if (replaced.count !== 1) return false;
        await tx.auditEvent.create({ data: { actorId: actor.id, businessId, targetId: existing.id,
          action: "STRIPE_LIVE_OAUTH_RECONNECTED" } });
        return true;
      }
      const [connection] = await tx.$queryRaw<{ id: string }[]>`
        INSERT INTO "StripeConnection" ("id", "businessId", "mode", "status", "stripeAccountId", "updatedAt")
        VALUES (${randomUUID()}, ${businessId}, 'LIVE', 'VERIFIED', ${accountId}, CURRENT_TIMESTAMP)
        ON CONFLICT DO NOTHING RETURNING "id"`;
      if (!connection) return false;
      await tx.stripeOAuthCredential.create({ data: { connectionId: connection.id, ...reference } });
      await tx.auditEvent.create({ data: { actorId: actor.id, businessId, targetId: connection.id, action: "STRIPE_LIVE_OAUTH_CONNECTED" } });
      return true;
    });
  const rotationFilter = (claim: RotationClaim) => ({
    connectionId: claim.connectionId,
    secretId: claim.reference.secretId,
    version: claim.reference.version,
    status: "REFRESHING" as const,
    operationId: claim.operationId
  });
  const oauthRotation: OAuthRotationStore = {
    claim: (businessId, mode, operationId, expected) => prisma.$transaction(async (tx) => {
      const updated = await tx.stripeOAuthCredential.updateMany({
        where: {
          status: "READY", secretId: expected?.secretId, version: expected?.version,
          connection: { businessId, mode, status: "VERIFIED", stripeAccountId: { not: null } }
        },
        data: { status: "REFRESHING", operationId }
      });
      if (updated.count !== 1) return null;
      const row = await tx.stripeOAuthCredential.findFirst({
        where: { operationId, status: "REFRESHING", connection: { businessId, mode, status: "VERIFIED" } },
        select: {
          connectionId: true, secretId: true, version: true,
          connection: { select: { stripeAccountId: true } }
        }
      });
      if (!row?.connection.stripeAccountId) return null;
      return {
        connectionId: row.connectionId, businessId, mode, operationId,
        accountId: row.connection.stripeAccountId,
        reference: { secretId: row.secretId, version: row.version }
      };
    }),
    release: async (claim) => (await prisma.stripeOAuthCredential.updateMany({
      where: rotationFilter(claim), data: { status: "READY", operationId: null }
    })).count === 1,
    complete: async (claim, version) => (await prisma.stripeOAuthCredential.updateMany({
      where: {
        ...rotationFilter(claim),
        connection: {
          businessId: claim.businessId, mode: claim.mode, status: "VERIFIED", stripeAccountId: claim.accountId
        }
      },
      data: { version, status: "READY", operationId: null }
    })).count === 1,
    requireReconnect: async (claim) => (await prisma.stripeOAuthCredential.updateMany({
      where: rotationFilter(claim), data: { status: "RECONNECT_REQUIRED", operationId: null }
    })).count === 1
  };
  const claimPublication = (
    id: string, current: "PENDING" | "PRODUCT_CREATED", next: "PRODUCT_CREATING" | "PRICE_CREATING"
  ) => prisma.$transaction(async (tx) => {
    const actors = await tx.$queryRaw<{ id: string }[]>`
      SELECT u."id" FROM "User" u JOIN "StripePublication" p ON p."actorId" = u."id"
      WHERE p."id" = ${id} AND u."sessionVersion" = p."actorSessionVersion" FOR UPDATE OF u`;
    if (!actors[0]) return null;
    const rows = await tx.$queryRaw<import("./generated/prisma/client.js").StripePublication[]>`
      UPDATE "StripePublication" p SET "status" = ${next}::"StripePublicationStatus",
        "operationId" = ${randomUUID()}, "claimedAt" = CURRENT_TIMESTAMP, "updatedAt" = CURRENT_TIMESTAMP
      WHERE p."id" = ${id} AND p."status" = ${current}::"StripePublicationStatus"
        AND EXISTS (SELECT 1 FROM "StripeConnection" c WHERE c."id" = p."connectionId" AND c."status" = 'VERIFIED')
        AND EXISTS (
          SELECT 1 FROM "User" u WHERE u."id" = p."actorId" AND u."sessionVersion" = p."actorSessionVersion"
            AND (u."role" = 'ADMIN' OR EXISTS (
              SELECT 1 FROM "Membership" m WHERE m."userId" = u."id" AND m."businessId" = p."businessId" AND m."role" = 'OWNER'
            ))
        )
      RETURNING p.*`;
    return rows[0] ?? null;
  });
  const publication: PublicationStore = {
    begin: (actor, businessId, draftId, mode) => prisma.$transaction(async (tx) => {
      await lockActiveActor(tx, actor);
      const rows = await tx.$queryRaw<import("./generated/prisma/client.js").StripePublication[]>`
        INSERT INTO "StripePublication"
          ("id", "draftId", "businessId", "actorId", "actorSessionVersion", "connectionId", "mode", "stripeAccountId",
           "name", "description", "kind", "amountCents", "currency", "billing", "interval", "updatedAt")
        SELECT ${randomUUID()}, p."id", p."businessId", ${actor.id}, ${actor.sessionVersion}, c."id", c."mode", c."stripeAccountId",
          p."name", p."description", p."kind", p."amountCents", p."currency", p."billing", p."interval", CURRENT_TIMESTAMP
        FROM "ProductDraft" p JOIN "Business" b ON b."id" = p."businessId"
        JOIN "StripeConnection" c ON c."businessId" = b."id"
        WHERE p."id" = ${draftId} AND b."id" = ${businessId} AND ${authorizedBusiness(actor)}
          AND c."mode" = ${mode}::"StripeMode" AND c."status" = 'VERIFIED' AND c."stripeAccountId" IS NOT NULL
        ON CONFLICT ("draftId", "mode") DO NOTHING
        RETURNING *`;
      if (rows[0]) {
        await tx.auditEvent.create({
          data: { actorId: actor.id, action: "STRIPE_PUBLICATION_STARTED", targetId: rows[0].id, businessId }
        });
      }
      return rows[0] ?? null;
    }),
    find: async (actor, businessId, id) => {
      const rows = await prisma.$queryRaw<import("./generated/prisma/client.js").StripePublication[]>`
        SELECT p.* FROM "StripePublication" p JOIN "Business" b ON b."id" = p."businessId"
        JOIN "StripeConnection" c ON c."id" = p."connectionId"
        WHERE p."id" = ${id} AND b."id" = ${businessId} AND p."actorId" = ${actor.id}
          AND p."actorSessionVersion" = ${actor.sessionVersion} AND c."status" = 'VERIFIED'
          AND ${authorizedBusiness(actor)}`;
      return rows[0] ?? null;
    },
    claimProduct: (id) => claimPublication(id, "PENDING", "PRODUCT_CREATING"),
    recordProduct: async (id, operationId, stripeProductId) => {
      if (!/^prod_[A-Za-z0-9]+$/.test(stripeProductId)) throw new Error("Invalid Stripe product ID");
      return (await prisma.stripePublication.updateMany({
        where: { id, operationId, status: "PRODUCT_CREATING" },
        data: { status: "PRODUCT_CREATED", operationId: null, claimedAt: null, stripeProductId }
      })).count === 1;
    },
    claimPrice: (id) => claimPublication(id, "PRODUCT_CREATED", "PRICE_CREATING"),
    recordPrice: async (id, operationId, stripePriceId) => {
      if (!/^price_[A-Za-z0-9]+$/.test(stripePriceId)) throw new Error("Invalid Stripe price ID");
      return (await prisma.stripePublication.updateMany({
        where: { id, operationId, status: "PRICE_CREATING" },
        data: { status: "PRICE_CREATED", operationId: null, claimedAt: null, stripePriceId }
      })).count === 1;
    }
  };
  const lockApprovedStorefront = async (tx: Prisma.TransactionClient, businessId: string, setup: CheckoutStorefront) => {
    if (setup.revision === null) return { origin: setup.origin, returnUrl: setup.dashboardReturnUrl };
    const [storefront] = await tx.$queryRaw<{ origin: string; returnUrl: string }[]>`
      SELECT "origin", "returnUrl" FROM "StorefrontProposal"
      WHERE "businessId" = ${businessId} AND "revision" = ${setup.revision}
        AND "origin" = ${setup.origin}
        ${setup.mode === "LIVE" ? Prisma.sql`AND "verifiedAt" IS NOT NULL` : Prisma.sql`AND "testApprovedAt" IS NOT NULL`}
        FOR SHARE`;
    return storefront;
  };
  const checkout: CheckoutStore = {
    begin: (businessId, publicationId, setup) => prisma.$transaction(async (tx) => {
      if (setup && !await lockApprovedStorefront(tx, businessId, setup)) return null;
      const orderId = randomUUID();
      const attemptId = randomUUID();
      const inserted = await tx.$executeRaw`
        INSERT INTO "CheckoutOrder" ("id", "publicationId", "storefrontRevision", "storefrontRequestId")
        SELECT ${orderId}, p."id", ${setup?.revision ?? null}, ${setup?.requestId ?? null} FROM "StripePublication" p
        JOIN "StripeConnection" c ON c."id" = p."connectionId"
        WHERE p."id" = ${publicationId} AND p."businessId" = ${businessId}
          AND p."status" = 'PRICE_CREATED' AND c."status" = 'VERIFIED'
          ${setup ? Prisma.sql`AND p."mode" = ${setup.mode ?? "TEST"}::"StripeMode" AND c."mode" = p."mode"` : Prisma.empty}
          ${setup?.connectionId ? Prisma.sql`AND c."id" = ${setup.connectionId}` : Prisma.empty}
          ${setup?.mode === "LIVE" ? Prisma.sql`AND EXISTS (SELECT 1 FROM "StripeOAuthCredential" credential
            WHERE credential."connectionId" = c."id" AND credential."status" = 'READY')`
            : setup?.connectionId ? Prisma.sql`AND p."billing" = 'ONE_TIME'` : Prisma.empty}
        ON CONFLICT ("publicationId", "storefrontRequestId") DO NOTHING`;
      if (inserted !== 1) return null;
      await tx.checkoutAttempt.create({ data: { id: attemptId, orderId } });
      return { orderId, attemptId };
    }),
    claim: (businessId, attemptId, setup) => prisma.$transaction(async (tx) => {
      const storefront = setup && await lockApprovedStorefront(tx, businessId, setup);
      if (setup && !storefront) return null;
      const operationId = randomUUID();
      const updated = await tx.checkoutAttempt.updateMany({
        where: {
          id: attemptId, status: "PENDING",
          order: {
            storefrontRevision: setup?.revision ?? null,
            storefrontRequestId: setup?.requestId ?? null,
            publication: {
              businessId, status: "PRICE_CREATED", mode: setup ? setup.mode ?? "TEST" : undefined,
              billing: setup?.connectionId && setup.mode !== "LIVE" ? "ONE_TIME" : undefined,
              connection: { id: setup?.connectionId, status: "VERIFIED", mode: setup ? setup.mode ?? "TEST" : undefined,
                oauthCredential: setup?.mode === "LIVE" ? { is: { status: "READY" } } : undefined }
            }
          }
        },
        data: { status: "CREATING", operationId, claimedAt: new Date() }
      });
      if (updated.count !== 1) return null;
      const { order, ...attempt } = await tx.checkoutAttempt.findUniqueOrThrow({
        where: { id: attemptId }, include: { order: { include: { publication: true } } }
      });
      const { publication: published, ...checkoutOrder } = order;
      return { attempt, order: checkoutOrder, publication: published, storefront };
    }),
    recordSession: async (attemptId, operationId, sessionId) => {
      if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(sessionId)) throw new Error("Invalid Stripe session ID");
      const mode = sessionId.startsWith("cs_live_") ? "LIVE" : "TEST";
      return prisma.$transaction(async (tx) => {
        const updated = await tx.checkoutAttempt.updateMany({
          where: { id: attemptId, operationId, status: "CREATING", order: { publication: { mode } } },
          data: { status: "SESSION_CREATED", operationId: null, claimedAt: null, stripeSessionId: sessionId }
        });
        if (updated.count !== 1) return false;
        await tx.$executeRaw`
          INSERT INTO "CheckoutRecoveryWork" ("attemptId", "nextAttemptAt")
          VALUES (${attemptId}, CURRENT_TIMESTAMP + INTERVAL '5 minutes')`;
        return true;
      });
    }
  };
  const checkoutWebhook: CheckoutWebhookStore = {
    record: (binding, event) => prisma.$transaction(async (tx) => {
      const inserted = await tx.$executeRaw`
        INSERT INTO "StripeCheckoutEvent"
          ("id", "connectionId", "businessId", "mode", "stripeAccountId", "source", "type", "sessionId", "eventCreated")
        SELECT ${event.id}, c."id", c."businessId", c."mode", c."stripeAccountId",
          ${binding.source}, ${event.type}, ${event.sessionId}, ${BigInt(event.created)}
        FROM "StripeConnection" c
        WHERE c."id" = ${binding.connectionId} AND c."businessId" = ${binding.businessId}
          AND c."mode" = ${binding.mode}::"StripeMode" AND c."stripeAccountId" = ${binding.accountId}
          AND c."status" = 'VERIFIED'
        ON CONFLICT ("id") DO NOTHING`;
      if (inserted === 1) {
        await tx.stripeCheckoutEventWork.create({ data: { eventId: event.id } });
        return "inserted";
      }
      const existing = await tx.stripeCheckoutEvent.findUnique({ where: { id: event.id } });
      if (!existing) throw new Error("Checkout webhook connection unavailable");
      if (existing.connectionId !== binding.connectionId || existing.businessId !== binding.businessId ||
          existing.mode !== binding.mode || existing.stripeAccountId !== binding.accountId ||
          existing.source !== binding.source || existing.type !== event.type || existing.sessionId !== event.sessionId ||
          existing.eventCreated !== BigInt(event.created)) {
        throw new Error("Conflicting checkout webhook event");
      }
      return "duplicate";
    })
  };
  const recordCheckoutObservation = async (
    tx: Prisma.TransactionClient,
    order: { id: string; initialPaymentStatus: "UNPAID" | "PAID"; paidQuantity: number | null },
    observation: CheckoutObservation
  ) => {
    if (observation.status === "PAID") {
      if (!Number.isInteger(observation.quantity) || observation.quantity < 1 || observation.quantity > 50) {
        throw new Error("Invalid paid quantity");
      }
      if (order.initialPaymentStatus === "PAID" && order.paidQuantity !== observation.quantity) {
        throw new Error("Conflicting checkout paid quantity");
      }
      if (order.initialPaymentStatus === "UNPAID") {
        await tx.checkoutOrder.update({
          where: { id: order.id },
          data: { initialPaymentStatus: "PAID", paidQuantity: observation.quantity }
        });
      }
    } else if (observation.status !== "UNPAID" || observation.quantity !== null) {
      throw new Error("Invalid checkout observation");
    }
  };
  const checkoutReconciliation: CheckoutReconciliationStore = {
    find: async (businessId, connectionId, eventId) => {
      const event = await prisma.stripeCheckoutEvent.findFirst({
        where: { id: eventId, businessId, connectionId, connection: { status: "VERIFIED" } }
      });
      if (!event) return null;
      const attempt = await prisma.checkoutAttempt.findFirst({
        where: {
          stripeSessionId: event.sessionId, status: "SESSION_CREATED",
          order: { publication: {
            businessId, connectionId, mode: event.mode, stripeAccountId: event.stripeAccountId
          } }
        },
        include: { order: { include: { publication: true } } }
      });
      if (!attempt) return null;
      const { order, ...checkoutAttempt } = attempt;
      const { publication: published, ...checkoutOrder } = order;
      return { event, order: checkoutOrder, attempt: checkoutAttempt, publication: published };
    },
    findAttempt: async (businessId, connectionId, attemptId) => {
      const attempt = await prisma.checkoutAttempt.findFirst({
        where: {
          id: attemptId, status: "SESSION_CREATED", stripeSessionId: { not: null },
          order: { publication: { businessId, connectionId, connection: { status: "VERIFIED" } } }
        },
        include: { order: { include: { publication: true } } }
      });
      if (!attempt) return null;
      const { order, ...checkoutAttempt } = attempt;
      const { publication: published, ...checkoutOrder } = order;
      return { order: checkoutOrder, attempt: checkoutAttempt, publication: published };
    },
    record: (businessId, connectionId, eventId, orderId, observation) => prisma.$transaction(async (tx) => {
      const orders = await tx.$queryRaw<{
        id: string; initialPaymentStatus: "UNPAID" | "PAID"; paidQuantity: number | null
      }[]>`
        SELECT o."id", o."initialPaymentStatus", o."paidQuantity"
        FROM "StripeCheckoutEvent" e
        JOIN "StripeConnection" c ON c."id" = e."connectionId" AND c."status" = 'VERIFIED'
        JOIN "CheckoutAttempt" a ON a."stripeSessionId" = e."sessionId" AND a."status" = 'SESSION_CREATED'
        JOIN "CheckoutOrder" o ON o."id" = a."orderId"
        JOIN "StripePublication" p ON p."id" = o."publicationId"
        WHERE e."id" = ${eventId} AND e."businessId" = ${businessId} AND e."connectionId" = ${connectionId}
          AND o."id" = ${orderId} AND p."businessId" = e."businessId" AND p."connectionId" = e."connectionId"
          AND p."mode" = e."mode" AND p."stripeAccountId" = e."stripeAccountId"
        FOR UPDATE OF o FOR SHARE OF c`;
      const order = orders[0];
      if (!order) throw new Error("Checkout event order unavailable");
      await recordCheckoutObservation(tx, order, observation);
      const inserted = await tx.$executeRaw`
        INSERT INTO "StripeCheckoutEventResult" ("eventId", "orderId", "observedStatus")
        VALUES (${eventId}, ${orderId}, ${observation.status}::"InitialCheckoutPaymentStatus")
        ON CONFLICT ("eventId") DO NOTHING`;
      if (!inserted) {
        const existing = await tx.stripeCheckoutEventResult.findUniqueOrThrow({ where: { eventId } });
        if (existing.orderId !== orderId) throw new Error("Conflicting checkout event result");
      }
    }),
    recordAttempt: (businessId, connectionId, attemptId, orderId, sessionId, observation) =>
      prisma.$transaction(async (tx) => {
        const orders = await tx.$queryRaw<{
          id: string; initialPaymentStatus: "UNPAID" | "PAID"; paidQuantity: number | null
        }[]>`
          SELECT o."id", o."initialPaymentStatus", o."paidQuantity"
          FROM "CheckoutAttempt" a
          JOIN "CheckoutOrder" o ON o."id" = a."orderId"
          JOIN "StripePublication" p ON p."id" = o."publicationId"
          JOIN "StripeConnection" c ON c."id" = p."connectionId" AND c."businessId" = p."businessId"
            AND c."mode" = p."mode" AND c."stripeAccountId" = p."stripeAccountId" AND c."status" = 'VERIFIED'
          WHERE a."id" = ${attemptId} AND a."status" = 'SESSION_CREATED' AND a."stripeSessionId" = ${sessionId}
            AND o."id" = ${orderId} AND p."businessId" = ${businessId} AND p."connectionId" = ${connectionId}
          FOR UPDATE OF o FOR SHARE OF c`;
        const order = orders[0];
        if (!order) throw new Error("Checkout attempt order unavailable");
        await recordCheckoutObservation(tx, order, observation);
        if (order.initialPaymentStatus === "UNPAID" && observation.status === "PAID") {
          await tx.auditEvent.create({
            data: { action: "CHECKOUT_PAYMENT_RECONCILED", targetId: orderId, businessId }
          });
        }
      })
  };
  const checkoutEventWork: CheckoutEventWorkStore = {
    claim: async (businessId, connectionId, leaseToken) => {
      const rows = await prisma.$queryRaw<{ eventId: string; leaseToken: string; attemptCount: number }[]>`
        UPDATE "StripeCheckoutEventWork" w
        SET "status" = 'PROCESSING', "leaseToken" = ${leaseToken},
          "leaseUntil" = CURRENT_TIMESTAMP + INTERVAL '2 minutes',
          "attemptCount" = LEAST(w."attemptCount"::bigint + 1, 2147483647)::integer
        WHERE w."eventId" = (
          SELECT candidate."eventId" FROM "StripeCheckoutEventWork" candidate
          JOIN "StripeCheckoutEvent" e ON e."id" = candidate."eventId"
          JOIN "StripeConnection" c ON c."id" = e."connectionId"
          WHERE e."businessId" = ${businessId} AND e."connectionId" = ${connectionId}
            AND c."status" = 'VERIFIED'
            AND ((candidate."status" = 'PENDING' AND candidate."nextAttemptAt" <= CURRENT_TIMESTAMP)
              OR (candidate."status" = 'PROCESSING' AND candidate."leaseUntil" <= CURRENT_TIMESTAMP))
          ORDER BY candidate."nextAttemptAt", candidate."eventId"
          FOR UPDATE OF candidate SKIP LOCKED LIMIT 1
        )
        RETURNING w."eventId", w."leaseToken", w."attemptCount"`;
      return rows[0] ?? null;
    },
    complete: async (eventId, leaseToken) => (await prisma.$executeRaw`
      UPDATE "StripeCheckoutEventWork"
      SET "status" = 'DONE', "leaseToken" = NULL, "leaseUntil" = NULL, "lastError" = NULL
      WHERE "eventId" = ${eventId} AND "status" = 'PROCESSING'
        AND "leaseToken" = ${leaseToken} AND "leaseUntil" > CURRENT_TIMESTAMP`) === 1,
    retry: async (eventId, leaseToken, error, delaySeconds) => (await prisma.$executeRaw`
      UPDATE "StripeCheckoutEventWork"
      SET "status" = 'PENDING', "leaseToken" = NULL, "leaseUntil" = NULL, "lastError" = ${error},
        "nextAttemptAt" = CURRENT_TIMESTAMP + ${delaySeconds} * INTERVAL '1 second'
      WHERE "eventId" = ${eventId} AND "status" = 'PROCESSING'
        AND "leaseToken" = ${leaseToken} AND "leaseUntil" > CURRENT_TIMESTAMP`) === 1
  };
  const checkoutRecoveryWork: CheckoutRecoveryWorkStore = {
    claim: async (businessId, connectionId, leaseToken) => {
      const rows = await prisma.$queryRaw<{
        attemptId: string; leaseToken: string; attemptCount: number; alreadyPaid: boolean
      }[]>`
        WITH candidate AS (
          SELECT w."attemptId", o."initialPaymentStatus" = 'PAID' AS "alreadyPaid"
          FROM "CheckoutRecoveryWork" w
          JOIN "CheckoutAttempt" a ON a."id" = w."attemptId" AND a."status" = 'SESSION_CREATED'
          JOIN "CheckoutOrder" o ON o."id" = a."orderId"
          JOIN "StripePublication" p ON p."id" = o."publicationId"
          JOIN "StripeConnection" c ON c."id" = p."connectionId" AND c."status" = 'VERIFIED'
          WHERE p."businessId" = ${businessId} AND p."connectionId" = ${connectionId}
            AND ((w."status" = 'PENDING' AND w."nextAttemptAt" <= CURRENT_TIMESTAMP)
              OR (w."status" = 'PROCESSING' AND w."leaseUntil" <= CURRENT_TIMESTAMP))
          ORDER BY w."nextAttemptAt", w."attemptId"
          FOR UPDATE OF w SKIP LOCKED LIMIT 1
        )
        UPDATE "CheckoutRecoveryWork" w
        SET "status" = 'PROCESSING', "leaseToken" = ${leaseToken},
          "leaseUntil" = CURRENT_TIMESTAMP + INTERVAL '2 minutes',
          "attemptCount" = LEAST(w."attemptCount"::bigint + 1, 2147483647)::integer
        FROM candidate
        WHERE w."attemptId" = candidate."attemptId"
        RETURNING w."attemptId", w."leaseToken", w."attemptCount", candidate."alreadyPaid"`;
      return rows[0] ?? null;
    },
    complete: async (attemptId, leaseToken) => (await prisma.$executeRaw`
      UPDATE "CheckoutRecoveryWork"
      SET "status" = 'DONE', "leaseToken" = NULL, "leaseUntil" = NULL, "lastError" = NULL
      WHERE "attemptId" = ${attemptId} AND "status" = 'PROCESSING'
        AND "leaseToken" = ${leaseToken} AND "leaseUntil" > CURRENT_TIMESTAMP`) === 1,
    retry: async (attemptId, leaseToken, error, delaySeconds) => (await prisma.$executeRaw`
      UPDATE "CheckoutRecoveryWork"
      SET "status" = 'PENDING', "leaseToken" = NULL, "leaseUntil" = NULL, "lastError" = ${error},
        "nextAttemptAt" = CURRENT_TIMESTAMP + ${delaySeconds} * INTERVAL '1 second'
      WHERE "attemptId" = ${attemptId} AND "status" = 'PROCESSING'
        AND "leaseToken" = ${leaseToken} AND "leaseUntil" > CURRENT_TIMESTAMP`) === 1
  };
  const bindPilotTestConnection = (actor: User, input: {
    businessId: string; accountId: string; secretId: string; version: string;
  }) => prisma.$transaction(async (tx) => {
    if ((await lockActiveActor(tx, actor)).role !== "ADMIN") return null;
    const [business] = await tx.$queryRaw<{ id: string }[]>`
      SELECT "id" FROM "Business" WHERE "id" = ${input.businessId} FOR UPDATE`;
    if (!business) return null;
    const key = { businessId: input.businessId, mode: "TEST" as const };
    const existing = await tx.stripeConnection.findUnique({
      where: { businessId_mode: key }, include: { credential: true, oauthCredential: true }
    });
    if (existing) {
      return existing.status === "VERIFIED" && existing.stripeAccountId === input.accountId &&
        !existing.oauthCredential && existing.credential?.secretId === input.secretId &&
        existing.credential.version === input.version ? existing.id : null;
    }
    const connection = await tx.stripeConnection.create({
      data: {
        ...key, stripeAccountId: input.accountId, status: "VERIFIED",
        credential: { create: { secretId: input.secretId, version: input.version } }
      }
    });
    await tx.auditEvent.create({
      data: { actorId: actor.id, businessId: input.businessId, targetId: connection.id, action: "STRIPE_TEST_CONNECTION_BOUND" }
    });
    return connection.id;
  });
  const findLiveOAuthCredential = async (businessId: string) => {
    const credential = await prisma.stripeOAuthCredential.findFirst({
      where: { status: "READY", connection: { businessId, mode: "LIVE", status: "VERIFIED" } },
      select: { secretId: true, version: true, connection: { select: { id: true, stripeAccountId: true } } }
    });
    if (!credential?.connection.stripeAccountId) return null;
    return { connectionId: credential.connection.id, accountId: credential.connection.stripeAccountId,
      reference: { secretId: credential.secretId, version: credential.version } };
  };
  const checkoutRecoveryBindings: CheckoutRecoveryBindingStore = {
    find: async (businessId, connectionId, mode) => {
      const connection = await prisma.stripeConnection.findFirst({
        where: { id: connectionId, businessId, mode, status: "VERIFIED" },
        select: { id: true, businessId: true, mode: true, stripeAccountId: true, credential: true }
      });
      if (!connection?.stripeAccountId || !connection.credential) return null;
      return {
        businessId: connection.businessId, connectionId: connection.id, accountId: connection.stripeAccountId,
        mode: connection.mode, reference: {
          secretId: connection.credential.secretId, version: connection.credential.version
        }
      };
    }
  };
  return {
    prisma, repository, oauthAttempts, oauthRotation, findLiveOAuthCredential, publication, checkout, checkoutWebhook,
    checkoutReconciliation, checkoutEventWork, checkoutRecoveryWork, checkoutRecoveryBindings,
    storefrontProposal, loginRateLimitStore, bindPilotTestConnection, sandboxOAuthBinding, liveOAuthState, bindLiveOAuth
  };
}
