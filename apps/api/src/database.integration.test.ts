import "dotenv/config";
import { execFile } from "node:child_process";
import { randomUUID, scryptSync } from "node:crypto";
import { resolve } from "node:path";
import { promisify } from "node:util";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { Pool } from "pg";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { createDatabase } from "./db.js";
import { hashPassword, verifyPassword } from "./security.js";
import { BusinessCredentialService } from "./secrets/business-credential-service.js";
import { vi } from "vitest";
import { SandboxOAuthService } from "./stripe/oauth-sandbox.js";
import { SandboxIdentityExchange } from "./stripe/oauth-sandbox-exchange.js";
import { PostgresRateLimitStore } from "./postgres-rate-limit-store.js";
import { AuthorizationChangedError, EmailInUseError } from "./repository.js";
import { PasswordRecovery } from "./password-recovery.js";
import { MfaRateLimitError, MfaStore } from "./mfa-store.js";
import { MfaCrypto } from "./mfa-crypto.js";
import { rotateMfaKey } from "./mfa-key-rotation.js";
import { generate } from "otplib";
import Stripe from "stripe";
import { ProductPublisher } from "./stripe/publish-product.js";
import { CheckoutService } from "./stripe/checkout-service.js";
import { CheckoutWebhookInbox, CheckoutWebhookReceiver } from "./stripe/checkout-webhook.js";
import { CheckoutReconciler } from "./stripe/checkout-reconciler.js";
import { CheckoutEventWorker } from "./stripe/checkout-event-worker.js";
import { CheckoutRecoveryWorker } from "./stripe/checkout-recovery-worker.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) throw new Error("TEST_DATABASE_URL must point to a dedicated local database ending in _test");
const parsed = new URL(databaseUrl);
if (!["postgres:", "postgresql:"].includes(parsed.protocol) ||
    !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname) ||
    !/^\/[a-zA-Z0-9_]+_test$/.test(parsed.pathname) || parsed.search || parsed.hash) {
  throw new Error("TEST_DATABASE_URL must point to a dedicated local database ending in _test");
}

const id = randomUUID();
const password = "integration-test-password";
const email = (role: string) => `${role}-${id}@example.com`;
const resolveStorefrontTxt = vi.fn<(name: string) => Promise<string[][]>>();
const {
  prisma, repository, oauthAttempts, oauthRotation, publication, checkout, checkoutWebhook,
  checkoutReconciliation, checkoutEventWork, checkoutRecoveryWork, checkoutRecoveryBindings,
  storefrontProposal, loginRateLimitStore, bindPilotTestConnection, sandboxOAuthBinding, liveOAuthState, bindLiveOAuth
} = createDatabase(databaseUrl, resolveStorefrontTxt);
const pool = new Pool({ connectionString: databaseUrl });
const PgStore = connectPgSimple(session);
let store: InstanceType<typeof PgStore>;
let app: ReturnType<typeof createApp>;
const createdBusinessIds: string[] = [];
const allEmails = ["admin", "a", "b", "new", "legacy", "race", "stale-admin", "denied-owner", "recovery", "recovery-stale", "recovery-ambiguous", "recovery-later", "draft-revoked", "mfa", "mfa-expired", "mfa-limit", "mfa-api", "mfa-pending", "mfa-replace", "mfa-rotation-a", "mfa-rotation-b", "mfa-rotation-pending", "mfa-recovery-admin", "mfa-recovery-user", "mfa-recovery-other-admin", "mfa-server-guard"].map(email);
const origin = "http://localhost:5173";
const recoveryDeliveryIds: string[] = [];
const rotationAuditIds: string[] = [];
let createdMfaKeyState = false;
const execFileAsync = promisify(execFile);

beforeEach(async () => {
  await prisma.loginRateLimit.deleteMany();
  store = new PgStore({ pool, tableName: "session", pruneSessionInterval: false });
  app = createApp({
    repository, store, secret: "integration-test-secret-at-least-32-characters", origin, production: false,
    storefront: { proposals: storefrontProposal }
  });
});

function firstCookie(headers: Record<string, unknown>): string {
  const cookies = headers["set-cookie"];
  if (!Array.isArray(cookies) || typeof cookies[0] !== "string") throw new Error("Missing session cookie");
  return cookies[0];
}

beforeAll(async () => {
  const [database] = await prisma.$queryRaw<{ occupied: boolean }[]>`
    SELECT EXISTS (
      SELECT 1 FROM "User" UNION ALL SELECT 1 FROM "Business"
      UNION ALL SELECT 1 FROM "session" UNION ALL SELECT 1 FROM "LoginRateLimit"
      UNION ALL SELECT 1 FROM "AuditEvent" UNION ALL SELECT 1 FROM "PasswordResetDelivery"
      UNION ALL SELECT 1 FROM "MfaKeyState"
    ) AS occupied`;
  if (database.occupied) throw new Error("Integration tests require a fresh, exclusive test database");
  await new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore).initialize();
  createdMfaKeyState = true;
  const passwordHash = await hashPassword(password);
  const admin = await prisma.user.create({ data: { email: email("admin"), passwordHash, role: "ADMIN" } });
  createdBusinessIds.push((await repository.createBusinessWithOwner(admin, "A", email("a"), passwordHash)).id);
  createdBusinessIds.push((await repository.createBusinessWithOwner(admin, "B", email("b"), passwordHash)).id);
  const salt = "01".repeat(16);
  const legacyHash = `scrypt:${salt}:${scryptSync(password, salt, 64).toString("hex")}`;
  await prisma.user.create({ data: { email: email("legacy"), passwordHash: legacyHash } });
}, 30000);

afterAll(async () => {
  try {
    const users = await prisma.user.findMany({ where: { email: { in: allEmails } }, select: { id: true } });
    for (const user of users) {
      await pool.query(`DELETE FROM "session" WHERE sess->>'userId' = $1 OR sess->'mfaPending'->>'userId' = $1`, [user.id]);
    }
    await prisma.auditEvent.deleteMany({ where: { actorId: { in: users.map((user) => user.id) } } });
    await prisma.auditEvent.deleteMany({ where: { id: { in: rotationAuditIds } } });
    await prisma.passwordResetDelivery.deleteMany({ where: { id: { in: recoveryDeliveryIds } } });
    await prisma.business.deleteMany({ where: { id: { in: createdBusinessIds } } });
    await prisma.user.deleteMany({ where: { email: { in: allEmails } } });
    if (createdMfaKeyState && await prisma.mfaAuthenticator.count() === 0) {
      await prisma.mfaKeyState.deleteMany({
        where: { id: "primary", fingerprint: new MfaCrypto("ab".repeat(32)).fingerprint }
      });
    }
  } finally {
    loginRateLimitStore.shutdown();
    await prisma.$disconnect();
    await pool.end();
  }
}, 30000);

async function login(role: string) {
  const agent = request.agent(app);
  const response = await agent.post("/api/login").set("Origin", origin).send({ email: email(role), password }).expect(200);
  const header = firstCookie(response.headers);
  return { agent, cookie: header.split(";")[0], header };
}

describe("PostgreSQL-backed authentication and tenant isolation", () => {
  it("reserves one sandbox OAuth connection and exposes it only after atomic token binding", async () => {
    const alice = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const bob = await prisma.user.findUniqueOrThrow({ where: { email: email("b") } });
    const business = await prisma.business.create({
      data: { name: "Sandbox OAuth test", memberships: { create: { userId: alice.id } } }
    });
    const account = "acct_sandboxBindingTest";
    const reference = { secretId: `kp-stripe-oauth-test-${randomUUID().replaceAll("-", "")}`, version: "1" };
    try {
      expect(await sandboxOAuthBinding.reserve(bob, business.id, account)).toBeNull();
      const reservations = await Promise.all([
        sandboxOAuthBinding.reserve(alice, business.id, account),
        sandboxOAuthBinding.reserve(alice, business.id, account)
      ]);
      const [connectionId] = reservations.filter((value) => value !== null);
      expect(reservations.filter((value) => value !== null)).toHaveLength(1);
      expect(await sandboxOAuthBinding.status(alice, business.id)).toBe("unavailable");
      expect(await sandboxOAuthBinding.complete(bob, business.id, connectionId, account, reference)).toBe(false);
      expect(await sandboxOAuthBinding.complete(alice, business.id, connectionId, "acct_other", reference)).toBe(false);
      expect(await sandboxOAuthBinding.complete(alice, business.id, connectionId, account, reference)).toBe(true);
      expect(await sandboxOAuthBinding.complete(alice, business.id, connectionId, account, reference)).toBe(false);
      expect(await sandboxOAuthBinding.status(alice, business.id)).toBe("connected");
      expect(await prisma.stripeOAuthCredential.findUnique({ where: { connectionId } }))
        .toMatchObject({ ...reference, status: "READY" });
    } finally {
      await prisma.auditEvent.deleteMany({ where: { businessId: business.id } });
      await prisma.business.delete({ where: { id: business.id } });
    }
  });

  it("isolates storefront proposals and binds DNS proof to the current revision", async () => {
    const alice = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const bob = await prisma.user.findUniqueOrThrow({ where: { email: email("b") } });
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const business = await prisma.business.create({
      data: { name: "Storefront proposal test", memberships: { create: { userId: alice.id } } }
    });
    createdBusinessIds.push(business.id);
    const input = {
      origin: "https://shop.example.com",
      returnUrl: "https://shop.example.com/checkout/return?session_id={CHECKOUT_SESSION_ID}"
    };
    try {
      const owner = request.agent(app);
      const outsider = request.agent(app);
      await owner.post("/api/login").set("Origin", origin).send({ email: alice.email, password }).expect(200);
      await outsider.post("/api/login").set("Origin", origin).send({ email: bob.email, password }).expect(200);
      const path = `/api/businesses/${business.id}/storefront`;
      await request(app).get(path).expect(401);
      await outsider.get(path).expect(404);
      await owner.get(path).expect(200, { proposal: null });
      await owner.put(path).set("Origin", "https://other.example").send(input).expect(403);
      await outsider.put(path).set("Origin", origin).send(input).expect(404);
      await owner.put(path).set("Origin", origin).send({ ...input, origin: "invalid-origin" }).expect(400);
      await owner.put(path).set("Origin", origin).send({ ...input, verifiedAt: new Date() }).expect(400);
      const response = await owner.put(path).set("Origin", origin).send(input).expect(200);
      const saved = await storefrontProposal.find(alice, business.id);
      if (!saved) throw new Error("Expected an authorized storefront proposal");
      expect(saved).toMatchObject({ businessId: business.id, ...input, verifiedAt: null });
      expect(response.body).toEqual({ proposal: { ...input, revision: saved.revision, verifiedAt: null, testApprovedAt: null,
        challenge: { name: "_kuzushi-pay.shop.example.com.", value: `kuzushi-pay-verification=${saved.revision}` }
      } });
      expect(await storefrontProposal.find(alice, business.id)).toEqual(saved);
      expect(await storefrontProposal.find(admin, business.id)).toEqual(saved);
      expect(await storefrontProposal.find(bob, business.id)).toBeNull();
      const adminAgent = request.agent(app);
      await adminAgent.post("/api/login").set("Origin", origin).send({ email: admin.email, password }).expect(200);
      const approvalPath = `${path}/approve-test`;
      await owner.post(approvalPath).set("Origin", origin).send({ revision: saved.revision }).expect(403);
      await adminAgent.post(approvalPath).set("Origin", origin).send({ revision: randomUUID() }).expect(409);
      const approved = await adminAgent.post(approvalPath).set("Origin", origin).send({ revision: saved.revision }).expect(200);
      expect(approved.body.proposal).toMatchObject({ verifiedAt: null, testApprovedAt: expect.any(String) });
      await adminAgent.post(approvalPath).set("Origin", origin).send({ revision: saved.revision }).expect(200, approved.body);
      expect(await prisma.auditEvent.count({
        where: { businessId: business.id, action: "STOREFRONT_TEST_APPROVED", targetId: saved.revision }
      })).toBe(1);
      expect(await storefrontProposal.save(bob, business.id, input)).toBeNull();
      await expect(storefrontProposal.save(
        alice, business.id, { ...input, returnUrl: "https://other.example/checkout?session_id={CHECKOUT_SESSION_ID}" }
      )).rejects.toThrow("Invalid storefront proposal");
      await expect(storefrontProposal.save(
        { ...alice, sessionVersion: alice.sessionVersion + 1 }, business.id, input
      )).rejects.toBeInstanceOf(AuthorizationChangedError);
      resolveStorefrontTxt.mockResolvedValueOnce([["stale-proof"]]);
      await owner.post(`${path}/verify`).set("Origin", origin).send({ revision: saved.revision })
        .expect(409, { error: "STOREFRONT_DNS_UNVERIFIED" });
      await outsider.post(`${path}/verify`).set("Origin", origin).send({ revision: saved.revision }).expect(404);
      expect(resolveStorefrontTxt).toHaveBeenCalledTimes(1);
      resolveStorefrontTxt.mockResolvedValueOnce([["kuzushi-pay-verification=", saved.revision]]);
      const verified = await owner.post(`${path}/verify`).set("Origin", origin).send({ revision: saved.revision }).expect(200);
      expect(verified.body.proposal).toMatchObject({
        revision: saved.revision, verifiedAt: expect.any(String)
      });
      let changedRevision: string | undefined;
      resolveStorefrontTxt.mockImplementationOnce(async () => {
        const changed = await storefrontProposal.save(admin, business.id, {
          ...input, returnUrl: "https://shop.example.com/return?session_id={CHECKOUT_SESSION_ID}"
        });
        changedRevision = changed?.revision;
        return [[`kuzushi-pay-verification=${saved.revision}`]];
      });
      expect(await storefrontProposal.verify(alice, business.id, saved.revision)).toBeNull();
      expect(resolveStorefrontTxt).toHaveBeenLastCalledWith("_kuzushi-pay.shop.example.com.");
      expect(changedRevision).toEqual(expect.any(String));
      expect(changedRevision).not.toBe(saved.revision);
      expect(await storefrontProposal.find(alice, business.id)).toMatchObject({
        revision: changedRevision, verifiedAt: null, testApprovedAt: null
      });
      await adminAgent.post(approvalPath).set("Origin", origin).send({ revision: saved.revision }).expect(409);
      expect(await prisma.auditEvent.count({
        where: { businessId: business.id, action: "STOREFRONT_DNS_VERIFIED", targetId: saved.revision }
      })).toBe(1);
      expect(await prisma.auditEvent.count({
        where: { businessId: business.id, action: "STOREFRONT_PROPOSED" }
      })).toBe(2);
      const membershipClient = await pool.connect();
      let pending: Promise<PromiseSettledResult<unknown>[]> | undefined;
      let committed = false;
      let settledEarly = false;
      try {
        await membershipClient.query("BEGIN");
        await membershipClient.query('DELETE FROM "Membership" WHERE "userId" = $1 AND "businessId" = $2',
          [alice.id, business.id]);
        pending = Promise.allSettled([storefrontProposal.save(alice, business.id, input)]);
        settledEarly = await Promise.race([
          pending.then(() => true),
          new Promise<false>((resolve) => setTimeout(() => resolve(false), 200))
        ]);
        await membershipClient.query("COMMIT");
        committed = true;
      } finally {
        if (!committed) await membershipClient.query("ROLLBACK");
        membershipClient.release();
      }
      expect(settledEarly).toBe(false);
      expect(await pending).toEqual([{ status: "fulfilled", value: null }]);
      expect(await storefrontProposal.find(alice, business.id)).toBeNull();
      expect(await storefrontProposal.save(alice, business.id, input)).toBeNull();
      await owner.get(path).expect(404);
    } finally {
      await prisma.auditEvent.deleteMany({
        where: { businessId: business.id, action: { in: ["STOREFRONT_PROPOSED", "STOREFRONT_DNS_VERIFIED", "STOREFRONT_TEST_APPROVED"] } }
      });
      await prisma.business.delete({ where: { id: business.id } });
      createdBusinessIds.splice(createdBusinessIds.indexOf(business.id), 1);
    }
  });

  it("refuses to start with MFA disabled when a recovery grant exists", async () => {
    const user = await prisma.user.create({ data: { email: email("mfa-server-guard"), passwordHash: "unused" } });
    await prisma.mfaRecoveryGrant.create({
      data: { userId: user.id, codeHash: "ab".repeat(32), expiresAt: new Date(Date.now() + 60_000) }
    });
    try {
      expect(await prisma.mfaAuthenticator.count()).toBe(0);
      await expect(execFileAsync(process.execPath, [
        resolve("node_modules", "tsx", "dist", "cli.mjs"), resolve("apps", "api", "src", "server.ts")
      ], {
        env: {
          ...process.env, DATABASE_URL: databaseUrl, NODE_ENV: "test", APP_ENV: "development",
          APP_ORIGIN: origin, MFA_ENABLED: "false", SESSION_SECRET: "server-test-secret-at-least-32-characters",
          PASSWORD_RESET_ENABLED: "false", STRIPE_OAUTH_SANDBOX_ENABLED: "false",
          STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED: "false"
        },
        timeout: 10000
      })).rejects.toThrow("Cannot disable MFA");
    } finally {
      await prisma.mfaRecoveryGrant.deleteMany({ where: { userId: user.id } });
    }
  }, 30000);

  it("requires MFA for enrollment and later sign-ins, including backup-code replay", async () => {
    const user = await prisma.user.create({
      data: { email: email("mfa-api"), passwordHash: await hashPassword(password) }
    });
    const old = await login("mfa-api");
    const mfa = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore);
    const protectedApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, mfa
    });
    await request(protectedApp).get("/api/me").set("Cookie", old.cookie).expect(401);
    await request(protectedApp).post("/api/mfa/setup").set("Origin", origin).send({}).expect(401);
    const agent = request.agent(protectedApp);
    const first = await agent.post("/api/login").set("Origin", origin)
      .send({ email: user.email, password }).expect(200);
    expect(first.body).toEqual({ mfa: "setup" });
    await agent.get("/api/me").expect(401);
    await agent.get("/api/businesses").expect(401);
    await agent.get("/api/mfa/status").expect(200, { mfa: "setup" });
    await agent.post("/api/mfa/setup").set("Origin", "https://evil.example").send({}).expect(403);
    const setup = await agent.post("/api/mfa/setup").set("Origin", origin).send({}).expect(200);
    expect(setup.body.secret).toMatch(/^[A-Z2-7]+$/);
    expect(setup.body.pendingSecret).toBeUndefined();
    const pending = await pool.query(`SELECT sess FROM "session" WHERE sess->'mfaPending'->>'userId' = $1`, [user.id]);
    expect(pending.rows).toHaveLength(1);
    expect(JSON.stringify(pending.rows[0])).not.toContain(setup.body.secret);
    const now = Date.now();
    const nearbyTokens = await Promise.all([-30_000, 0, 30_000].map((offset) =>
      generate({ secret: setup.body.secret, epoch: Math.floor((now + offset) / 1000) })
    ));
    const wrongToken = ["000000", "000001", "000002", "000003"].find((code) => !nearbyTokens.includes(code));
    if (!wrongToken) throw new Error("Unable to select an invalid MFA token");
    await agent.post("/api/mfa/confirm").set("Origin", origin).send({ code: wrongToken })
      .expect(400, { error: "INVALID_MFA" });
    expect(await prisma.auditEvent.count({ where: { actorId: user.id, targetId: user.id, action: "MFA_ENROLLMENT_FAILED" } })).toBe(1);
    const token = await generate({ secret: setup.body.secret });
    const confirmed = await agent.post("/api/mfa/confirm").set("Origin", origin).send({ code: token }).expect(200);
    expect(confirmed.body.backupCodes).toHaveLength(10);
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await request(app).get("/api/me").set("Cookie", old.cookie).expect(503, { error: "MFA_UNAVAILABLE" });
      await request(app).post("/api/login").set("Origin", origin)
        .send({ email: user.email, password }).expect(503, { error: "MFA_UNAVAILABLE" });
    } finally { logs.mockRestore(); }
    await agent.get("/api/me").expect(200);
    await agent.post("/api/logout").set("Origin", origin).send({}).expect(200);
    await agent.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "challenge" });
    await agent.post("/api/mfa/verify").set("Origin", origin).send({ code: confirmed.body.backupCodes[0] }).expect(200);
    await agent.post("/api/logout").set("Origin", origin).send({}).expect(200);
    await agent.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "challenge" });
    await agent.post("/api/mfa/verify").set("Origin", origin).send({ code: confirmed.body.backupCodes[0] }).expect(400, { error: "INVALID_MFA" });
    const failures = await prisma.auditEvent.findMany({
      where: { actorId: user.id, action: { in: ["MFA_ENROLLMENT_FAILED", "MFA_CHALLENGE_FAILED"] } }
    });
    expect(failures.map((event) => event.action).sort()).toEqual(["MFA_CHALLENGE_FAILED", "MFA_ENROLLMENT_FAILED"]);
    expect(JSON.stringify(failures)).not.toContain(wrongToken);
    expect(JSON.stringify(failures)).not.toContain(confirmed.body.backupCodes[0]);
    expect(await repository.changePassword(user.id, user.passwordHash, "new-test-hash")).toBe(true);
    await agent.post("/api/mfa/verify").set("Origin", origin).send({ code: confirmed.body.backupCodes[1] }).expect(401);
  }, 30000);

  it("expires password-verified MFA sessions before setup", async () => {
    const user = await prisma.user.create({
      data: { email: email("mfa-pending"), passwordHash: await hashPassword(password) }
    });
    const mfa = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore);
    const protectedApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, mfa
    });
    const agent = request.agent(protectedApp);
    await agent.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "setup" });
    await pool.query(`UPDATE "session" SET sess = jsonb_set(sess::jsonb, '{mfaPending,startedAt}', '0'::jsonb)::json
      WHERE sess->'mfaPending'->>'userId' = $1`, [user.id]);
    await agent.get("/api/mfa/status").expect(200, { mfa: null });
    await agent.post("/api/mfa/setup").set("Origin", origin).send({}).expect(401);
    expect(await prisma.mfaAuthenticator.findUnique({ where: { userId: user.id } })).toBeNull();
  }, 30000);

  it("replaces backup codes only after a fresh factor and invalidates the old set", async () => {
    const user = await prisma.user.create({
      data: { email: email("mfa-replace"), passwordHash: await hashPassword(password) }
    });
    const mfa = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore);
    const protectedApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, mfa
    });
    const agent = request.agent(protectedApp);
    await agent.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200);
    await agent.post("/api/mfa/backup-codes").set("Origin", origin).send({ code: "invalid" }).expect(401);
    const setup = await agent.post("/api/mfa/setup").set("Origin", origin).send({}).expect(200);
    const token = await generate({ secret: setup.body.secret });
    const enrolled = await agent.post("/api/mfa/confirm").set("Origin", origin).send({ code: token }).expect(200);
    await agent.post("/api/mfa/backup-codes").set("Origin", origin).send({ code: "invalid" }).expect(400);
    const [first, second] = await Promise.all([
      agent.post("/api/mfa/backup-codes").set("Origin", origin).send({ code: enrolled.body.backupCodes[0] }),
      agent.post("/api/mfa/backup-codes").set("Origin", origin).send({ code: enrolled.body.backupCodes[0] })
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 400]);
    const replaced = first.status === 200 ? first : second;
    expect(replaced.body.backupCodes).toHaveLength(10);
    expect(await prisma.auditEvent.count({ where: { actorId: user.id, action: "MFA_BACKUP_CODES_REPLACED" } })).toBe(1);
    expect(await prisma.auditEvent.count({
      where: { actorId: user.id, targetId: user.id, action: "MFA_BACKUP_CODES_REPLACEMENT_FAILED" }
    })).toBe(2);
    await agent.post("/api/logout").set("Origin", origin).send({}).expect(200);
    await agent.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200);
    await agent.post("/api/mfa/verify").set("Origin", origin).send({ code: enrolled.body.backupCodes[1] }).expect(400);
    await agent.post("/api/mfa/verify").set("Origin", origin).send({ code: replaced.body.backupCodes[0] }).expect(200);
  }, 30000);

  it("requires verified administrator assistance and a single-use recovery code for MFA recovery", async () => {
    const passwordHash = await hashPassword(password);
    const administrator = await prisma.user.create({
      data: { email: email("mfa-recovery-admin"), passwordHash, role: "ADMIN" }
    });
    const user = await prisma.user.create({ data: { email: email("mfa-recovery-user"), passwordHash } });
    const otherAdmin = await prisma.user.create({
      data: { email: email("mfa-recovery-other-admin"), passwordHash, role: "ADMIN" }
    });
    const mfa = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore);
    const enroll = async (account: typeof user) => {
      const prepared = mfa.prepareEnrollment(account.id, account.email);
      const token = await generate({ secret: prepared.secret });
      const result = await mfa.enroll(account.id, account.sessionVersion, prepared.pendingSecret, token);
      if (!result) throw new Error("Expected MFA enrollment");
      return result;
    };
    const adminFactor = await enroll(administrator);
    const userFactor = await enroll(user);
    await enroll(otherAdmin);
    const makeApp = () => createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, mfa
    });
    const admin = request.agent(makeApp());
    await admin.post("/api/login").set("Origin", origin).send({ email: administrator.email, password }).expect(200);
    await admin.post("/api/mfa/verify").set("Origin", origin).send({ code: adminFactor.backupCodes[0] }).expect(200);
    const victim = request.agent(makeApp());
    await victim.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200);
    await victim.post("/api/mfa/verify").set("Origin", origin).send({ code: userFactor.backupCodes[0] }).expect(200);
    const pending = request.agent(makeApp());
    await pending.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200);
    const body = { email: user.email, code: adminFactor.backupCodes[1], identityVerified: true };
    await victim.post("/api/admin/mfa-recovery").set("Origin", origin).send(body).expect(403);
    await admin.post("/api/admin/mfa-recovery").set("Origin", origin)
      .send({ ...body, identityVerified: false }).expect(400);
    await admin.post("/api/admin/mfa-recovery").set("Origin", origin)
      .send({ ...body, email: administrator.email }).expect(400, { error: "INVALID_RECOVERY_TARGET" });
    await admin.post("/api/admin/mfa-recovery").set("Origin", origin)
      .send({ ...body, email: otherAdmin.email }).expect(400, { error: "INVALID_RECOVERY_TARGET" });
    await prisma.user.update({ where: { id: administrator.id }, data: { role: "USER" } });
    try {
      expect(await mfa.issueRecovery(administrator.id, adminFactor.sessionVersion, user.email, adminFactor.backupCodes[3]))
        .toEqual({ status: "unauthenticated" });
    } finally {
      await prisma.user.update({ where: { id: administrator.id }, data: { role: "ADMIN" } });
    }
    await admin.post("/api/admin/mfa-recovery").set("Origin", origin)
      .send({ ...body, code: "incorrect" }).expect(400, { error: "INVALID_MFA" });
    await prisma.$executeRaw`ALTER TABLE "AuditEvent" ADD CONSTRAINT "test_mfa_recovery_audit_failure"
      CHECK ("action" <> 'MFA_RECOVERY_ISSUED') NOT VALID`;
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await admin.post("/api/admin/mfa-recovery").set("Origin", origin).send(body).expect(500);
      expect(await prisma.mfaAuthenticator.findUnique({ where: { userId: user.id } })).not.toBeNull();
      expect(await prisma.mfaRecoveryGrant.findUnique({ where: { userId: user.id } })).toBeNull();
      expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).sessionVersion).toBe(userFactor.sessionVersion);
    } finally {
      logs.mockRestore();
      await prisma.$executeRaw`ALTER TABLE "AuditEvent" DROP CONSTRAINT "test_mfa_recovery_audit_failure"`;
    }
    const issuanceStartedAt = Date.now();
    const [first, second] = await Promise.all([
      admin.post("/api/admin/mfa-recovery").set("Origin", origin).send(body),
      admin.post("/api/admin/mfa-recovery").set("Origin", origin).send(body)
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 400]);
    const recoveryCode = (first.status === 200 ? first : second).body.recoveryCode as string;
    expect(recoveryCode).toMatch(/^[a-f0-9]{64}$/);
    const grant = await prisma.mfaRecoveryGrant.findUniqueOrThrow({ where: { userId: user.id } });
    expect(grant.codeHash).not.toBe(recoveryCode);
    expect(grant.expiresAt.getTime()).toBeGreaterThanOrEqual(issuanceStartedAt + 30 * 60_000);
    expect(grant.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 30 * 60_000);
    expect(await prisma.mfaAuthenticator.findUnique({ where: { userId: user.id } })).toBeNull();
    expect(await prisma.mfaBackupCode.count({ where: { userId: user.id } })).toBe(0);
    await victim.get("/api/me").expect(401);
    await pending.post("/api/mfa/verify").set("Origin", origin).send({ code: userFactor.backupCodes[1] }).expect(401);
    expect(await prisma.auditEvent.count({ where: { actorId: administrator.id, targetId: user.id, action: "MFA_RECOVERY_ISSUED" } })).toBe(1);

    const recovery = request.agent(makeApp());
    await recovery.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "recovery" });
    await recovery.post("/api/mfa/setup").set("Origin", origin).send({}).expect(403, { error: "MFA_RECOVERY_REQUIRED" });
    await recovery.post("/api/mfa/recovery").set("Origin", origin).send({ code: "0".repeat(64) })
      .expect(400, { error: "INVALID_RECOVERY_CODE" });
    await recovery.post("/api/mfa/recovery").set("Origin", origin).send({ code: recoveryCode }).expect(200, { mfa: "setup" });
    await prisma.mfaRecoveryGrant.update({ where: { userId: user.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    await recovery.post("/api/mfa/setup").set("Origin", origin).send({}).expect(400, { error: "INVALID_RECOVERY_CODE" });
    const reissued = await admin.post("/api/admin/mfa-recovery").set("Origin", origin)
      .send({ ...body, code: adminFactor.backupCodes[2] }).expect(200);
    await recovery.post("/api/mfa/recovery").set("Origin", origin).send({ code: reissued.body.recoveryCode }).expect(401);
    const retry = request.agent(makeApp());
    await retry.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "recovery" });
    await retry.post("/api/mfa/recovery").set("Origin", origin).send({ code: recoveryCode })
      .expect(400, { error: "INVALID_RECOVERY_CODE" });
    await retry.post("/api/mfa/recovery").set("Origin", origin).send({ code: reissued.body.recoveryCode }).expect(200);
    const setup = await retry.post("/api/mfa/setup").set("Origin", origin).send({}).expect(200);
    const competing = request.agent(makeApp());
    await competing.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "recovery" });
    await competing.post("/api/mfa/recovery").set("Origin", origin).send({ code: reissued.body.recoveryCode }).expect(200);
    const competingSetup = await competing.post("/api/mfa/setup").set("Origin", origin).send({}).expect(200);
    const [enrolled, competingEnrollment] = await Promise.all([
      retry.post("/api/mfa/confirm").set("Origin", origin).send({ code: await generate({ secret: setup.body.secret }) }),
      competing.post("/api/mfa/confirm").set("Origin", origin).send({ code: await generate({ secret: competingSetup.body.secret }) })
    ]);
    expect([enrolled.status, competingEnrollment.status].filter((status) => status === 200)).toHaveLength(1);
    expect([enrolled.status, competingEnrollment.status].filter((status) => status === 400 || status === 401)).toHaveLength(1);
    expect(await prisma.mfaRecoveryGrant.findUnique({ where: { userId: user.id } })).toBeNull();
    const winner = enrolled.status === 200 ? retry : competing;
    await winner.post("/api/logout").set("Origin", origin).send({}).expect(200);
    await winner.post("/api/login").set("Origin", origin).send({ email: user.email, password }).expect(200, { mfa: "challenge" });
    await winner.post("/api/mfa/verify").set("Origin", origin).send({ code: userFactor.backupCodes[1] }).expect(400);
  }, 30000);

  it("rotates MFA keys atomically, rejects stale instances and invalidates pending sessions", async () => {
    const knownUsers = await prisma.user.findMany({ where: { email: { in: allEmails } }, select: { id: true } });
    const knownIds = knownUsers.map((user) => user.id);
    const unrelatedFactors = await prisma.mfaAuthenticator.count({ where: { userId: { notIn: knownIds } } });
    const unrelatedPending = await pool.query<{ count: number }>(`
      SELECT COUNT(*)::int AS count FROM "session"
      WHERE sess::jsonb ? 'mfaPending' AND NOT COALESCE(sess->'mfaPending'->>'userId' = ANY($1::text[]), false)`, [knownIds]);
    if (unrelatedFactors || unrelatedPending.rows[0].count) {
      throw new Error("The test database contains unrelated MFA factors or pending sessions");
    }
    const first = await prisma.user.create({ data: { id: `mfa-rot-a-${id}`, email: email("mfa-rotation-a"), passwordHash: "unused" } });
    const second = await prisma.user.create({ data: { id: `mfa-rot-b-${id}`, email: email("mfa-rotation-b"), passwordHash: "unused" } });
    let now = 1_700_000_000_000;
    const oldKey = "ab".repeat(32);
    const newKey = "cd".repeat(32);
    const oldStore = new MfaStore(prisma, oldKey, loginRateLimitStore, () => now);
    const pendingUser = await prisma.user.create({
      data: { email: email("mfa-rotation-pending"), passwordHash: await hashPassword(password) }
    });
    const oldApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, mfa: oldStore
    });
    const agent = request.agent(oldApp);
    const loginResponse = await agent.post("/api/login").set("Origin", origin)
      .send({ email: pendingUser.email, password }).expect(200);
    const cookie = firstCookie(loginResponse.headers).split(";")[0];
    const setup = await agent.post("/api/mfa/setup").set("Origin", origin).send({}).expect(200);
    const pendingSession = await pool.query<{ sid: string; sess: object; expire: Date }>(
      `SELECT sid, sess, expire FROM "session" WHERE sess->'mfaPending'->>'userId' = $1`, [pendingUser.id]
    );
    expect(pendingSession.rows).toHaveLength(1);
    const a = oldStore.prepareEnrollment(first.id, first.email);
    const b = oldStore.prepareEnrollment(second.id, second.email);
    const codeA = await generate({ secret: a.secret, epoch: Math.floor(now / 1000) });
    const codeB = await generate({ secret: b.secret, epoch: Math.floor(now / 1000) });
    const enrolledA = await oldStore.enroll(first.id, first.sessionVersion, a.pendingSecret, codeA);
    const enrolledB = await oldStore.enroll(second.id, second.sessionVersion, b.pendingSecret, codeB);
    if (!enrolledA || !enrolledB) throw new Error("Expected MFA enrollments");
    const initialA = await prisma.mfaAuthenticator.findUniqueOrThrow({ where: { userId: first.id } });
    const initialB = await prisma.mfaAuthenticator.findUniqueOrThrow({ where: { userId: second.id } });
    const corrupted = Buffer.from(initialB.secret, "base64");
    corrupted[0] ^= 1;
    await prisma.mfaAuthenticator.update({ where: { userId: second.id }, data: { secret: corrupted.toString("base64") } });
    try {
      await expect(rotateMfaKey(prisma, oldKey, newKey)).rejects.toThrow();
      expect((await prisma.mfaAuthenticator.findUniqueOrThrow({ where: { userId: first.id } })).secret).toBe(initialA.secret);
      expect((await prisma.mfaKeyState.findUniqueOrThrow({ where: { id: "primary" } })).fingerprint)
        .toBe(new MfaCrypto(oldKey).fingerprint);
    } finally {
      await prisma.mfaAuthenticator.update({ where: { userId: second.id }, data: { secret: initialB.secret } });
    }
    const sid = `mfa-rotation-${id}`;
    await pool.query('INSERT INTO "session" (sid, sess, expire) VALUES ($1, $2::json, $3)', [
      sid, JSON.stringify({ mfaPending: { userId: first.id } }), new Date(Date.now() + 60_000)
    ]);
    let rotated = false;
    try {
      const expectedCount = await prisma.mfaAuthenticator.count();
      const locker = await pool.connect();
      let pending: ReturnType<typeof rotateMfaKey> | undefined;
      let finishedEarly = false;
      let committed = false;
      try {
        await locker.query("BEGIN");
        await locker.query('SELECT "id" FROM "MfaKeyState" WHERE "id" = $1 FOR SHARE', ["primary"]);
        pending = rotateMfaKey(prisma, oldKey, newKey);
        finishedEarly = await Promise.race([
          pending.then(() => true, () => true),
          new Promise<false>((resolve) => setTimeout(() => resolve(false), 200))
        ]);
        await locker.query("COMMIT");
        committed = true;
      } finally {
        if (!committed) await locker.query("ROLLBACK");
        locker.release();
      }
      if (!pending) throw new Error("Missing rotation attempt");
      const result = await pending;
      rotated = true;
      rotationAuditIds.push(result.auditId);
      expect(finishedEarly).toBe(false);
      expect(result.count).toBe(expectedCount);
      expect((await pool.query('SELECT sid FROM "session" WHERE sid = $1', [sid])).rows).toHaveLength(0);
      await expect(oldStore.verify(first.id, enrolledA.sessionVersion, enrolledA.backupCodes[0])).rejects.toThrow("MFA encryption key does not match");
      await expect(oldStore.initialize()).rejects.toThrow("MFA encryption key does not match");
      const newStore = new MfaStore(prisma, newKey, loginRateLimitStore, () => now);
      await newStore.initialize();
      const staleSession = pendingSession.rows[0];
      await pool.query('INSERT INTO "session" (sid, sess, expire) VALUES ($1, $2::json, $3)', [
        staleSession.sid, JSON.stringify(staleSession.sess), staleSession.expire
      ]);
      const newApp = createApp({
        repository, store, secret: "integration-test-secret-at-least-32-characters",
        origin, production: false, mfa: newStore
      });
      await request(newApp).get("/api/mfa/status").set("Cookie", cookie).expect(200, { mfa: null });
      const staleCode = await generate({ secret: setup.body.secret });
      await request(newApp).post("/api/mfa/confirm").set("Cookie", cookie).set("Origin", origin)
        .send({ code: staleCode }).expect(401);
      expect(await prisma.mfaAuthenticator.findUnique({ where: { userId: pendingUser.id } })).toBeNull();
      now += 30_000;
      const next = await generate({ secret: a.secret, epoch: Math.floor(now / 1000) });
      expect(await newStore.verify(first.id, enrolledA.sessionVersion, next)).toBe(true);
      expect(await newStore.verify(second.id, enrolledB.sessionVersion, enrolledB.backupCodes[0])).toBe(true);
      const existingAudits = await prisma.auditEvent.findMany({
        where: { action: "MFA_KEY_ROTATED" }, select: { id: true }
      });
      const cli = [resolve("node_modules", "tsx", "dist", "cli.mjs"), resolve("apps", "api", "src", "mfa-rotate-key.ts")];
      const cliEnv = {
        ...process.env, DATABASE_URL: databaseUrl, NODE_ENV: "test", APP_ENV: "development",
        APP_ORIGIN: origin, MFA_ENABLED: "true", MFA_KEY: newKey, MFA_ROTATION_CONFIRM: "rotate",
        SESSION_SECRET: "ef".repeat(32), PASSWORD_RESET_ENABLED: "false",
        PASSWORD_RESET_KEY: "12".repeat(32), STRIPE_OAUTH_SANDBOX_ENABLED: "false",
        STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED: "false"
      };
      await expect(execFileAsync(process.execPath, cli, {
        env: { ...cliEnv, MFA_NEW_KEY: cliEnv.SESSION_SECRET }, timeout: 30000
      })).rejects.toThrow();
      expect((await prisma.mfaKeyState.findUniqueOrThrow({ where: { id: "primary" } })).fingerprint)
        .toBe(new MfaCrypto(newKey).fingerprint);
      try {
        const output = await execFileAsync(process.execPath, cli, {
          env: { ...cliEnv, MFA_NEW_KEY: oldKey }, timeout: 30000
        });
        expect(output.stdout).toContain(`completed for ${expectedCount} authenticators`);
      } finally {
        const state = await prisma.mfaKeyState.findUniqueOrThrow({ where: { id: "primary" } });
        rotated = state.fingerprint !== new MfaCrypto(oldKey).fingerprint;
        const newAudits = await prisma.auditEvent.findMany({
          where: { action: "MFA_KEY_ROTATED", id: { notIn: existingAudits.map((event) => event.id) } },
          select: { id: true }
        });
        rotationAuditIds.push(...newAudits.map((event) => event.id));
      }
      expect(rotated).toBe(false);
    } finally {
      await pool.query('DELETE FROM "session" WHERE sid = $1', [sid]);
      if (rotated) rotationAuditIds.push((await rotateMfaKey(prisma, newKey, oldKey)).auditId);
    }
  }, 30000);

  it("encrypts MFA secrets and atomically consumes authenticator and backup codes", async () => {
    const user = await prisma.user.create({ data: { email: email("mfa"), passwordHash: "original-test-hash" } });
    let now = 1_700_000_000_000;
    const mfa = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore, () => now);
    const { secret, pendingSecret } = mfa.prepareEnrollment(user.id, user.email);
    expect(pendingSecret).not.toContain(secret);
    const token = await generate({ secret, epoch: Math.floor(now / 1000) });
    const tampered = Buffer.from(pendingSecret, "base64");
    tampered[0] ^= 1;
    await expect(mfa.enroll(user.id, user.sessionVersion, tampered.toString("base64"), token)).rejects.toThrow();
    expect(await mfa.enroll(user.id, user.sessionVersion, pendingSecret, "invalid")).toBeNull();
    const enrollment = await Promise.all([
      mfa.enroll(user.id, user.sessionVersion, pendingSecret, token),
      mfa.enroll(user.id, user.sessionVersion, pendingSecret, token)
    ]);
    const successes = enrollment.filter((result) => result !== null);
    expect(successes).toHaveLength(1);
    const enrolled = successes[0];
    if (!enrolled) throw new Error("Expected MFA enrollment");
    const factor = await prisma.mfaAuthenticator.findUniqueOrThrow({ where: { userId: user.id } });
    expect(factor.secret).not.toContain(secret);
    const storedCodes = await prisma.mfaBackupCode.findMany({ where: { userId: user.id } });
    expect(storedCodes).toHaveLength(10);
    expect(storedCodes.map((item) => item.codeHash)).not.toContain(enrolled.backupCodes[0]);
    expect(await mfa.verify(user.id, enrolled.sessionVersion, token)).toBe(false);
    expect(await mfa.verify(user.id, user.sessionVersion, enrolled.backupCodes[0])).toBe(false);
    now += 30_000;
    const next = await generate({ secret, epoch: Math.floor(now / 1000) });
    const otpResults = await Promise.all([
      mfa.verify(user.id, enrolled.sessionVersion, next),
      mfa.verify(user.id, enrolled.sessionVersion, next)
    ]);
    expect(otpResults.filter(Boolean)).toHaveLength(1);
    const backupResults = await Promise.all([
      mfa.verify(user.id, enrolled.sessionVersion, enrolled.backupCodes[0]),
      mfa.verify(user.id, enrolled.sessionVersion, enrolled.backupCodes[0])
    ]);
    expect(backupResults.filter(Boolean)).toHaveLength(1);
    expect(await prisma.mfaBackupCode.count({ where: { userId: user.id } })).toBe(9);
    expect(await repository.changePassword(user.id, user.passwordHash, "new-test-hash")).toBe(true);
    expect(await mfa.verify(user.id, enrolled.sessionVersion, enrolled.backupCodes[1])).toBe(false);
    expect(await mfa.verify(user.id, enrolled.sessionVersion + 1, enrolled.backupCodes[1])).toBe(true);
    now += 30_000;
    const wrongKey = new MfaStore(prisma, "cd".repeat(32), loginRateLimitStore, () => now);
    const later = await generate({ secret, epoch: Math.floor(now / 1000) });
    await expect(wrongKey.verify(user.id, enrolled.sessionVersion + 1, later)).rejects.toThrow();
    expect(await prisma.auditEvent.count({ where: { actorId: user.id, action: "MFA_ENROLLED" } })).toBe(1);
    expect(await prisma.auditEvent.count({ where: { actorId: user.id, action: "MFA_CHALLENGE_SUCCEEDED" } })).toBe(3);
  }, 30000);

  it("rechecks an enrollment code after waiting for a user lock", async () => {
    const user = await prisma.user.create({ data: { email: email("mfa-expired"), passwordHash: "unused" } });
    let now = 1_700_000_000_000;
    const mfa = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore, () => now);
    const { secret, pendingSecret } = mfa.prepareEnrollment(user.id, user.email);
    const token = await generate({ secret, epoch: Math.floor(now / 1000) });
    const other = mfa.prepareEnrollment(randomUUID(), user.email);
    await expect(mfa.enroll(user.id, user.sessionVersion, other.pendingSecret, token)).rejects.toThrow();
    const client = await pool.connect();
    let pending: ReturnType<MfaStore["enroll"]> | undefined;
    let committed = false;
    try {
      await client.query("BEGIN");
      await client.query('SELECT "id" FROM "User" WHERE "id" = $1 FOR UPDATE', [user.id]);
      pending = mfa.enroll(user.id, user.sessionVersion, pendingSecret, token);
      await new Promise((resolve) => setTimeout(resolve, 200));
      now += 120_000;
      await client.query("COMMIT");
      committed = true;
    } finally {
      if (!committed) await client.query("ROLLBACK");
      client.release();
    }
    expect(await pending).toBeNull();
    expect(await prisma.mfaAuthenticator.findUnique({ where: { userId: user.id } })).toBeNull();
  }, 30000);

  it("shares MFA attempt limits between instances without storing user identifiers", async () => {
    const user = await prisma.user.create({ data: { email: email("mfa-limit"), passwordHash: "unused" } });
    const first = new MfaStore(prisma, "ab".repeat(32), loginRateLimitStore);
    const secondStore = new PostgresRateLimitStore(prisma);
    const second = new MfaStore(prisma, "ab".repeat(32), secondStore);
    const { secret, pendingSecret } = first.prepareEnrollment(user.id, user.email);
    try {
      for (let attempt = 0; attempt < 10; attempt++) {
        expect(await (attempt % 2 ? first : second).enroll(user.id, user.sessionVersion, pendingSecret, "invalid")).toBeNull();
      }
      await expect(first.enroll(user.id, user.sessionVersion, pendingSecret, "invalid")).rejects.toBeInstanceOf(MfaRateLimitError);
      const counters = await prisma.loginRateLimit.findMany();
      expect(counters).toHaveLength(1);
      expect(counters[0].key).not.toContain(user.id);
      expect(counters[0].totalHits).toBe(11);
      vi.spyOn(secondStore, "increment").mockRejectedValueOnce(new Error("rate store unavailable"));
      await expect(second.enroll(user.id, user.sessionVersion, pendingSecret, "invalid")).rejects.toThrow("rate store unavailable");
      await prisma.loginRateLimit.update({
        where: { key: counters[0].key }, data: { resetTime: new Date(Date.now() - 1000) }
      });
      const token = await generate({ secret });
      expect(await first.enroll(user.id, user.sessionVersion, pendingSecret, token)).not.toBeNull();
    } finally {
      secondStore.shutdown();
    }
  }, 30000);

  it("verifies the required database tables through readiness", async () => {
    await request(app).get("/health/ready").expect(200, { status: "ok" });
  });

  it("isolates product drafts and rechecks membership for database writes", async () => {
    const alice = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const bob = await prisma.user.findUniqueOrThrow({ where: { email: email("b") } });
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const input = {
      name: "Test session", description: "A draft", kind: "SERVICE" as const, amountCents: 5000,
      billing: "RECURRING" as const, interval: "MONTH" as const
    };
    expect(await repository.createProductDraft(bob, createdBusinessIds[0], input)).toBeNull();
    const created = await repository.createProductDraft(alice, createdBusinessIds[0], input);
    if (!created) throw new Error("Expected an authorized draft");
    try {
      expect(await repository.listProductDrafts(bob, createdBusinessIds[0])).toEqual([]);
      expect(await repository.updateProductDraft(bob, createdBusinessIds[0], created.id, input)).toBeNull();
      expect(await repository.updateProductDraft(admin, createdBusinessIds[0], created.id, { ...input, amountCents: 7000 }))
        .toMatchObject({ amountCents: 7000 });
      expect(await prisma.auditEvent.findMany({
        where: { targetId: created.id }, select: { actorId: true, action: true, businessId: true },
        orderBy: { action: "asc" }
      })).toEqual([
        { actorId: alice.id, action: "PRODUCT_DRAFT_CREATED", businessId: createdBusinessIds[0] },
        { actorId: admin.id, action: "PRODUCT_DRAFT_UPDATED", businessId: createdBusinessIds[0] }
      ]);
      await prisma.membership.delete({ where: { userId_businessId: { userId: alice.id, businessId: createdBusinessIds[0] } } });
      expect(await repository.listProductDrafts(alice, createdBusinessIds[0])).toEqual([]);
      expect(await repository.updateProductDraft(alice, createdBusinessIds[0], created.id, input)).toBeNull();
      expect(await repository.createProductDraft(alice, createdBusinessIds[0], input)).toBeNull();
    } finally {
      await prisma.membership.upsert({
        where: { userId_businessId: { userId: alice.id, businessId: createdBusinessIds[0] } },
        create: { userId: alice.id, businessId: createdBusinessIds[0], role: "OWNER" }, update: {}
      });
      await prisma.productDraft.delete({ where: { id: created.id } });
    }
  });

  it("persists immutable authorized publication snapshots and serializes Stripe operation claims", async () => {
    const alice = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const bob = await prisma.user.findUniqueOrThrow({ where: { email: email("b") } });
    const business = await prisma.business.create({
      data: { name: "Publication test", memberships: { create: { userId: alice.id } } }
    });
    createdBusinessIds.push(business.id);
    try {
      const draft = await repository.createProductDraft(alice, business.id, {
        name: "Original", description: "Test", kind: "SERVICE", amountCents: 5000,
        billing: "RECURRING", interval: "MONTH"
      });
      if (!draft) throw new Error("Expected an authorized draft");
      expect(await publication.begin(alice, business.id, draft.id, "TEST")).toBeNull();
      const connection = await prisma.stripeConnection.create({
        data: { businessId: business.id, mode: "TEST", status: "VERIFIED", stripeAccountId: "acct_publication" }
      });
      expect(await publication.begin(bob, business.id, draft.id, "TEST")).toBeNull();
      expect(await publication.begin(alice, business.id, draft.id, "LIVE")).toBeNull();
      await expect(publication.begin({ ...alice, sessionVersion: alice.sessionVersion - 1 }, business.id, draft.id, "TEST"))
        .rejects.toBeInstanceOf(AuthorizationChangedError);
      const outcomes = await Promise.all([
        publication.begin(alice, business.id, draft.id, "TEST"),
        publication.begin(alice, business.id, draft.id, "TEST")
      ]);
      const [snapshot] = outcomes.filter((value) => value !== null);
      expect(outcomes.filter((value) => value !== null)).toHaveLength(1);
      if (!snapshot) throw new Error("Expected a publication snapshot");
      expect(snapshot).toMatchObject({
        businessId: business.id, draftId: draft.id, connectionId: connection.id, mode: "TEST",
        stripeAccountId: "acct_publication", name: "Original", amountCents: 5000,
        billing: "RECURRING", interval: "MONTH", status: "PENDING"
      });
      expect(await publication.find(bob, business.id, snapshot.id)).toBeNull();
      expect(await publication.find(alice, createdBusinessIds[0], snapshot.id)).toBeNull();
      expect(await publication.find(alice, business.id, snapshot.id)).toMatchObject({ id: snapshot.id });
      await repository.updateProductDraft(alice, business.id, draft.id, {
        name: "Changed", description: "Test", kind: "SERVICE", amountCents: 7000,
        billing: "ONE_TIME", interval: null
      });
      expect(await prisma.stripePublication.findUniqueOrThrow({ where: { id: snapshot.id } }))
        .toMatchObject({ name: "Original", amountCents: 5000, billing: "RECURRING", interval: "MONTH" });
      await expect(prisma.stripePublication.update({
        where: { id: snapshot.id }, data: { amountCents: 1 }
      })).rejects.toThrow();
      await expect(prisma.stripePublication.update({
        where: { id: snapshot.id }, data: { status: "PRICE_CREATED", stripeProductId: "prod_bad", stripePriceId: "price_bad" }
      })).rejects.toThrow();
      await expect(prisma.stripeConnection.update({
        where: { id: connection.id }, data: { stripeAccountId: "acct_other" }
      })).rejects.toThrow();
      await prisma.membership.delete({ where: { userId_businessId: { userId: alice.id, businessId: business.id } } });
      expect(await publication.find(alice, business.id, snapshot.id)).toBeNull();
      expect(await publication.claimProduct(snapshot.id)).toBeNull();
      await prisma.membership.create({ data: { userId: alice.id, businessId: business.id, role: "OWNER" } });
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "DISCONNECTED" } });
      expect(await publication.claimProduct(snapshot.id)).toBeNull();
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "VERIFIED" } });
      const claims = await Promise.all([publication.claimProduct(snapshot.id), publication.claimProduct(snapshot.id)]);
      expect(claims.filter((value) => value !== null)).toHaveLength(1);
      const claim = claims.find((value) => value !== null);
      if (!claim?.operationId || !claim.claimedAt) throw new Error("Expected a product claim");
      expect(await publication.claimProduct(snapshot.id)).toBeNull();
      expect(await publication.recordProduct(snapshot.id, randomUUID(), "prod_123")).toBe(false);
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "DISCONNECTED" } });
      expect(await publication.recordProduct(snapshot.id, claim.operationId, "prod_123")).toBe(true);
      expect(await publication.claimPrice(snapshot.id)).toBeNull();
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "VERIFIED" } });
      const priceClaim = await publication.claimPrice(snapshot.id);
      if (!priceClaim?.operationId) throw new Error("Expected a price claim");
      expect(await publication.claimPrice(snapshot.id)).toBeNull();
      expect(await publication.recordPrice(snapshot.id, randomUUID(), "price_123")).toBe(false);
      expect(await publication.recordPrice(snapshot.id, priceClaim.operationId, "price_123")).toBe(true);
      expect(await prisma.stripePublication.findUniqueOrThrow({ where: { id: snapshot.id } }))
        .toMatchObject({ status: "PRICE_CREATED", stripeProductId: "prod_123", stripePriceId: "price_123" });
      await expect(prisma.stripePublication.update({
        where: { id: snapshot.id }, data: { stripeProductId: "prod_other" }
      })).rejects.toThrow();
      await expect(prisma.stripePublication.update({
        where: { id: snapshot.id }, data: { status: "PENDING", stripeProductId: null, stripePriceId: null }
      })).rejects.toThrow();
    } finally {
      await prisma.stripePublication.deleteMany({ where: { businessId: business.id } });
      await prisma.business.delete({ where: { id: business.id } });
      createdBusinessIds.splice(createdBusinessIds.indexOf(business.id), 1);
    }
  });

  it("publishes through the durable store using a mocked Stripe account", async () => {
    const alice = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const business = await prisma.business.create({
      data: { name: "Publication flow test", memberships: { create: { userId: alice.id } } }
    });
    createdBusinessIds.push(business.id);
    try {
      const binding = { businessId: business.id, accountId: "acct_publicationflow",
        secretId: `kp-stripe-test-${randomUUID().replaceAll("-", "")}`, version: "1" };
      expect(await bindPilotTestConnection(alice, binding)).toBeNull();
      const connectionId = await bindPilotTestConnection(admin, binding);
      if (!connectionId) throw new Error("Expected a verified test connection");
      expect(await bindPilotTestConnection(admin, binding)).toBe(connectionId);
      expect(await bindPilotTestConnection(admin, { ...binding, version: "2" })).toBeNull();
      expect(await prisma.auditEvent.count({
        where: { businessId: business.id, action: "STRIPE_TEST_CONNECTION_BOUND" }
      })).toBe(1);
      const connection = await prisma.stripeConnection.findUniqueOrThrow({ where: { id: connectionId } });
      const draft = await repository.createProductDraft(alice, business.id, {
        name: "Class", description: "", kind: "SERVICE", amountCents: 5000,
        billing: "ONE_TIME", interval: null
      });
      if (!draft) throw new Error("Expected an authorized draft");
      const client = {
        accounts: { retrieveCurrent: vi.fn().mockResolvedValue({ object: "account", id: "acct_publicationflow" }) },
        balance: { retrieve: vi.fn().mockResolvedValue({ object: "balance", livemode: false }) },
        products: {
          retrieve: vi.fn(),
          create: vi.fn(async (params: Stripe.ProductCreateParams) => {
            const publicationId = params.metadata?.kuzushi_publication_id;
            if (typeof publicationId !== "string") throw new Error("Missing publication metadata");
            return {
              id: "prod_flow", object: "product", livemode: false, active: true,
              name: params.name, description: null,
              metadata: { kuzushi_publication_id: publicationId, kuzushi_kind: "SERVICE" }
            };
          })
        },
        prices: {
          create: vi.fn(async (params: Stripe.PriceCreateParams) => {
            const publicationId = params.metadata?.kuzushi_publication_id;
            if (typeof publicationId !== "string") throw new Error("Missing publication metadata");
            return {
              id: "price_flow", object: "price", active: true, livemode: false, currency: "usd",
              unit_amount: 5000, type: "one_time", product: "prod_flow", billing_scheme: "per_unit",
              custom_unit_amount: null, transform_quantity: null, recurring: null,
              metadata: { kuzushi_publication_id: publicationId }
            };
          })
        }
      };
      const publisher = new ProductPublisher(publication, client);
      const { publicationId } = await publisher.begin(alice, business.id, draft.id, "TEST");
      await expect(publisher.resume(alice, business.id, publicationId))
        .resolves.toEqual({ productId: "prod_flow", priceId: "price_flow" });
      expect(await prisma.stripePublication.findUniqueOrThrow({ where: { id: publicationId } }))
        .toMatchObject({ status: "PRICE_CREATED", stripeProductId: "prod_flow", stripePriceId: "price_flow" });
      expect(client.products.create).toHaveBeenCalledOnce();
      expect(client.prices.create).toHaveBeenCalledOnce();
      expect(await checkout.begin(createdBusinessIds[0], publicationId)).toBeNull();
      const checkoutClient = {
        accounts: client.accounts,
        prices: { retrieve: vi.fn().mockResolvedValue({
          id: "price_flow", object: "price", active: true, livemode: false, currency: "usd",
          unit_amount: 5000, type: "one_time", product: "prod_flow", billing_scheme: "per_unit",
          custom_unit_amount: null, transform_quantity: null, recurring: null
        }) },
        checkout: { sessions: { create: vi.fn(async (params: Stripe.Checkout.SessionCreateParams) => {
          const orderId = params.metadata?.kuzushi_order_id;
          const attemptId = params.metadata?.kuzushi_attempt_id;
          if (typeof orderId !== "string" || typeof attemptId !== "string") throw new Error("Missing checkout metadata");
          return {
            id: "cs_test_flow", object: "checkout.session", livemode: false, status: "open", mode: "payment",
            ui_mode: "embedded_page", currency: "usd", amount_subtotal: 5000, automatic_tax: { enabled: true },
            metadata: { kuzushi_order_id: orderId, kuzushi_attempt_id: attemptId },
            client_secret: "cs_test_flow_secret_fixture"
          };
        }) } }
      };
      const storefront = await storefrontProposal.save(alice, business.id, {
        origin: "https://store.example",
        returnUrl: "https://store.example/checkout/return?session_id={CHECKOUT_SESSION_ID}"
      });
      if (!storefront) throw new Error("Expected storefront proposal");
      const setup = { origin: storefront.origin, revision: storefront.revision, connectionId: connection.id, requestId: randomUUID() };
      const checkoutService = new CheckoutService(checkout, checkoutClient, business.id, setup);
      await expect(checkoutService.begin(publicationId)).rejects.toThrow("UNAVAILABLE");
      await storefrontProposal.approveTest(admin, business.id, setup.revision);
      expect(await checkout.begin(business.id, publicationId, { ...setup, origin: "https://other.example" })).toBeNull();
      expect(await checkout.begin(business.id, publicationId, { ...setup, connectionId: randomUUID() })).toBeNull();
      const started = await checkoutService.begin(publicationId);
      await expect(checkoutService.begin(publicationId)).rejects.toThrow("UNAVAILABLE");
      expect(await checkout.claim(createdBusinessIds[0], started.attemptId)).toBeNull();
      expect(await checkout.claim(business.id, started.attemptId)).toBeNull();
      const results = await Promise.allSettled([
        checkoutService.create(started.attemptId), checkoutService.create(started.attemptId)
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
      expect(checkoutClient.checkout.sessions.create).toHaveBeenCalledOnce();
      expect(checkoutClient.checkout.sessions.create.mock.calls[0][0].return_url).toBe(storefront.returnUrl);
      const staleService = new CheckoutService(checkout, checkoutClient, business.id, { ...setup, requestId: randomUUID() });
      const stale = await staleService.begin(publicationId);
      await storefrontProposal.save(alice, business.id, {
        origin: storefront.origin, returnUrl: "https://store.example/new-return?session_id={CHECKOUT_SESSION_ID}"
      });
      await expect(staleService.create(stale.attemptId)).rejects.toThrow("UNAVAILABLE");
      expect(checkoutClient.checkout.sessions.create).toHaveBeenCalledOnce();
      expect(await prisma.checkoutAttempt.findUniqueOrThrow({ where: { id: started.attemptId } }))
        .toMatchObject({ orderId: started.orderId, status: "SESSION_CREATED", stripeSessionId: "cs_test_flow" });
      await expect(prisma.checkoutAttempt.update({
        where: { id: started.attemptId }, data: { status: "PENDING", stripeSessionId: null }
      })).rejects.toThrow();
      const next = await checkout.begin(business.id, publicationId);
      if (!next) throw new Error("Expected a second checkout");
      const claimed = await checkout.claim(business.id, next.attemptId);
      if (!claimed?.attempt.operationId) throw new Error("Expected a checkout claim");
      expect(await checkout.claim(business.id, next.attemptId)).toBeNull();
      expect(await checkout.recordSession(next.attemptId, randomUUID(), "cs_test_other")).toBe(false);
      expect(await checkout.recordSession(next.attemptId, claimed.attempt.operationId, "cs_live_other")).toBe(false);
      expect(await prisma.checkoutRecoveryWork.findUnique({ where: { attemptId: next.attemptId } })).toBeNull();
      await prisma.checkoutRecoveryWork.create({ data: { attemptId: next.attemptId } });
      await expect(checkout.recordSession(next.attemptId, claimed.attempt.operationId, "cs_test_other")).rejects.toThrow();
      expect(await prisma.checkoutAttempt.findUniqueOrThrow({ where: { id: next.attemptId } }))
        .toMatchObject({ status: "CREATING", stripeSessionId: null });
      await prisma.checkoutRecoveryWork.delete({ where: { attemptId: next.attemptId } });
      expect(await checkout.recordSession(next.attemptId, claimed.attempt.operationId, "cs_test_other")).toBe(true);

      const secret = "whsec_databaseFixture";
      const inbox = new CheckoutWebhookInbox({
        connectionId: connection.id, businessId: business.id, accountId: "acct_publicationflow",
        mode: "TEST", source: "direct"
      }, [secret], checkoutWebhook);
      const event = {
        id: "evt_databaseFixture", object: "event", type: "checkout.session.completed",
        created: 1_700_000_000, livemode: false,
        data: { object: { id: "cs_test_flow", object: "checkout.session", customer_email: "private@example.com" } }
      };
      const body = JSON.stringify(event);
      const signature = Stripe.webhooks.generateTestHeaderString({ payload: body, secret });
      const deliveries = await Promise.all(Array.from({ length: 5 }, () => inbox.accept(Buffer.from(body), signature)));
      expect(deliveries.filter((result) => result === "inserted")).toHaveLength(1);
      expect(deliveries.filter((result) => result === "duplicate")).toHaveLength(4);
      expect(await prisma.stripeCheckoutEventWork.count({ where: { eventId: event.id } })).toBe(1);
      const saved = await prisma.stripeCheckoutEvent.findUniqueOrThrow({ where: { id: event.id } });
      expect(saved).toMatchObject({
        businessId: business.id, connectionId: connection.id, mode: "TEST", stripeAccountId: "acct_publicationflow",
        type: event.type, sessionId: "cs_test_flow", eventCreated: BigInt(event.created)
      });
      expect(saved).not.toHaveProperty("customer_email");
      const reconciliationClient = {
        accounts: client.accounts,
        checkout: { sessions: {
          retrieve: vi.fn().mockResolvedValue({
            id: "cs_test_flow", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
            ui_mode: "embedded_page", payment_status: "unpaid", currency: "usd", amount_total: 10000,
            automatic_tax: { enabled: true },
            metadata: { kuzushi_order_id: started.orderId, kuzushi_attempt_id: started.attemptId }
          }),
          listLineItems: vi.fn().mockResolvedValue({
            object: "list", has_more: false, data: [{
              object: "item", quantity: 2, currency: "usd",
              price: {
                id: "price_flow", object: "price", active: true, livemode: false, currency: "usd",
                unit_amount: 5000, type: "one_time", product: "prod_flow", billing_scheme: "per_unit",
                custom_unit_amount: null, transform_quantity: null, recurring: null
              }
            }]
          })
        } }
      };
      const reconciler = new CheckoutReconciler(checkoutReconciliation, reconciliationClient, business.id, connection.id);
      const worker = new CheckoutEventWorker(
        checkoutEventWork, checkoutReconciliation, reconciliationClient, business.id, connection.id
      );
      expect(await checkoutEventWork.claim(createdBusinessIds[0], connection.id, randomUUID())).toBeNull();
      const claims = await Promise.all(Array.from({ length: 5 }, () =>
        checkoutEventWork.claim(business.id, connection.id, randomUUID())
      ));
      const firstClaim = claims.find((claim) => claim !== null);
      expect(claims.filter(Boolean)).toHaveLength(1);
      if (!firstClaim) throw new Error("Expected a work claim");
      await prisma.stripeCheckoutEventWork.update({
        where: { eventId: event.id }, data: { leaseUntil: new Date(0) }
      });
      expect(await checkoutEventWork.complete(event.id, firstClaim.leaseToken)).toBe(false);
      const recovered = await checkoutEventWork.claim(business.id, connection.id, randomUUID());
      if (!recovered) throw new Error("Expected an expired work lease to be recovered");
      expect(recovered.attemptCount).toBe(2);
      expect(await checkoutEventWork.complete(event.id, firstClaim.leaseToken)).toBe(false);
      expect(await checkoutEventWork.retry(event.id, firstClaim.leaseToken, "NOT_READY", 30)).toBe(false);
      expect(await checkoutEventWork.retry(event.id, recovered.leaseToken, "NOT_READY", 30)).toBe(true);
      expect(await worker.processOne()).toEqual({ state: "idle" });
      await prisma.stripeCheckoutEventWork.update({
        where: { eventId: event.id }, data: { nextAttemptAt: new Date(0) }
      });
      expect(await worker.processOne()).toEqual({ state: "completed", observedStatus: "UNPAID" });
      expect(await worker.processOne()).toEqual({ state: "idle" });
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: started.orderId } }))
        .toMatchObject({ initialPaymentStatus: "UNPAID", paidQuantity: null });
      reconciliationClient.checkout.sessions.retrieve.mockResolvedValue({
        id: "cs_test_flow", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
        ui_mode: "embedded_page", payment_status: "paid", currency: "usd", amount_total: 10000,
        automatic_tax: { enabled: true },
        metadata: { kuzushi_order_id: started.orderId, kuzushi_attempt_id: started.attemptId }
      });
      expect(await Promise.all(Array.from({ length: 5 }, () => reconciler.reconcile(event.id))))
        .toEqual(Array.from({ length: 5 }, () => ({ observedStatus: "PAID" })));
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: started.orderId } }))
        .toMatchObject({ initialPaymentStatus: "PAID", paidQuantity: 2 });
      expect(await prisma.stripeCheckoutEventResult.findUniqueOrThrow({ where: { eventId: event.id } }))
        .toMatchObject({ orderId: started.orderId, observedStatus: "UNPAID" });
      reconciliationClient.checkout.sessions.retrieve.mockResolvedValue({
        id: "cs_test_other", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
        ui_mode: "embedded_page", payment_status: "unpaid", currency: "usd", amount_total: 10000,
        automatic_tax: { enabled: true },
        metadata: { kuzushi_order_id: next.orderId, kuzushi_attempt_id: next.attemptId }
      });
      expect(await reconciler.reconcileAttempt(next.attemptId))
        .toEqual({ observedStatus: "UNPAID", sessionStatus: "complete" });
      expect(await prisma.stripeCheckoutEvent.count({ where: { sessionId: "cs_test_other" } })).toBe(0);
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: next.orderId } }))
        .toMatchObject({ initialPaymentStatus: "UNPAID", paidQuantity: null });
      reconciliationClient.checkout.sessions.retrieve.mockResolvedValue({
        id: "cs_test_other", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
        ui_mode: "embedded_page", payment_status: "paid", currency: "usd", amount_total: 10000,
        automatic_tax: { enabled: true },
        metadata: { kuzushi_order_id: next.orderId, kuzushi_attempt_id: next.attemptId }
      });
      expect(await Promise.all(Array.from({ length: 5 }, () => reconciler.reconcileAttempt(next.attemptId))))
        .toEqual(Array.from({ length: 5 }, () => ({ observedStatus: "PAID", sessionStatus: "complete" })));
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: next.orderId } }))
        .toMatchObject({ initialPaymentStatus: "PAID", paidQuantity: 2 });
      expect(await prisma.auditEvent.count({
        where: { businessId: business.id, targetId: next.orderId, action: "CHECKOUT_PAYMENT_RECONCILED" }
      })).toBe(1);
      await checkoutReconciliation.recordAttempt(
        business.id, connection.id, next.attemptId, next.orderId, "cs_test_other",
        { status: "UNPAID", quantity: null }
      );
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: next.orderId } }))
        .toMatchObject({ initialPaymentStatus: "PAID", paidQuantity: 2 });
      expect(await checkoutReconciliation.findAttempt(createdBusinessIds[0], connection.id, next.attemptId)).toBeNull();
      await expect(checkoutReconciliation.recordAttempt(
        createdBusinessIds[0], connection.id, next.attemptId, next.orderId, "cs_test_other",
        { status: "PAID", quantity: 2 }
      )).rejects.toThrow("Checkout attempt order unavailable");
      await expect(checkoutReconciliation.recordAttempt(
        business.id, connection.id, next.attemptId, next.orderId, "cs_test_flow",
        { status: "PAID", quantity: 2 }
      )).rejects.toThrow("Checkout attempt order unavailable");
      await expect(checkoutReconciliation.recordAttempt(
        business.id, connection.id, next.attemptId, next.orderId, "cs_test_other",
        { status: "PAID", quantity: 3 }
      )).rejects.toThrow("Conflicting checkout paid quantity");
      const laterBody = JSON.stringify({
        ...event, id: "evt_later", data: { object: { id: "cs_test_other", object: "checkout.session" } }
      });
      expect(await inbox.accept(
        Buffer.from(laterBody), Stripe.webhooks.generateTestHeaderString({ payload: laterBody, secret })
      )).toBe("inserted");
      expect(await worker.processOne()).toEqual({ state: "completed", observedStatus: "PAID" });
      expect(await prisma.stripeCheckoutEventResult.findUniqueOrThrow({ where: { eventId: "evt_later" } }))
        .toMatchObject({ orderId: next.orderId, observedStatus: "PAID" });
      const earlyBody = JSON.stringify({
        ...event, id: "evt_early", data: { object: { id: "cs_test_notRecorded", object: "checkout.session" } }
      });
      expect(await inbox.accept(
        Buffer.from(earlyBody), Stripe.webhooks.generateTestHeaderString({ payload: earlyBody, secret })
      )).toBe("inserted");
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "DISCONNECTED" } });
      expect(await worker.processOne()).toEqual({ state: "idle" });
      await expect(checkoutReconciliation.record(
        business.id, connection.id, event.id, started.orderId, { status: "UNPAID", quantity: null }
      )).rejects.toThrow("Checkout event order unavailable");
      expect(await checkoutReconciliation.findAttempt(business.id, connection.id, next.attemptId)).toBeNull();
      await expect(checkoutReconciliation.recordAttempt(
        business.id, connection.id, next.attemptId, next.orderId, "cs_test_other",
        { status: "UNPAID", quantity: null }
      )).rejects.toThrow("Checkout attempt order unavailable");
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "VERIFIED" } });
      await expect(reconciler.reconcile("evt_early")).rejects.toMatchObject({ code: "NOT_READY" });
      expect(await worker.processOne()).toEqual({ state: "retry", error: "NOT_READY" });
      expect(await prisma.stripeCheckoutEventWork.findUniqueOrThrow({ where: { eventId: "evt_early" } }))
        .toMatchObject({ status: "PENDING", attemptCount: 1, lastError: "NOT_READY" });
      expect(await prisma.stripeCheckoutEventResult.findUnique({ where: { eventId: "evt_early" } })).toBeNull();
      await checkoutReconciliation.record(business.id, connection.id, event.id, started.orderId, { status: "UNPAID", quantity: null });
      await expect(checkoutReconciliation.record(
        business.id, connection.id, event.id, started.orderId, { status: "PAID", quantity: 3 }
      )).rejects.toThrow("Conflicting checkout paid quantity");
      expect(await checkoutReconciliation.find(createdBusinessIds[0], connection.id, event.id)).toBeNull();
      await expect(checkoutReconciliation.record(
        createdBusinessIds[0], connection.id, event.id, started.orderId, { status: "PAID", quantity: 2 }
      )).rejects.toThrow("Checkout event order unavailable");
      const late = await checkout.begin(business.id, publicationId);
      if (!late) throw new Error("Expected a checkout for the early event");
      const lateClaim = await checkout.claim(business.id, late.attemptId);
      if (!lateClaim?.attempt.operationId) throw new Error("Expected a late checkout claim");
      expect(await checkout.recordSession(late.attemptId, lateClaim.attempt.operationId, "cs_test_notRecorded")).toBe(true);
      await prisma.stripeCheckoutEventWork.update({
        where: { eventId: "evt_early" }, data: { nextAttemptAt: new Date(0) }
      });
      client.accounts.retrieveCurrent.mockRejectedValueOnce(new Error("Stripe unavailable"));
      expect(await worker.processOne()).toEqual({ state: "retry", error: "STRIPE_UNAVAILABLE" });
      expect(await prisma.stripeCheckoutEventWork.findUniqueOrThrow({ where: { eventId: "evt_early" } }))
        .toMatchObject({ status: "PENDING", attemptCount: 2, lastError: "STRIPE_UNAVAILABLE" });
      await prisma.stripeCheckoutEventWork.update({
        where: { eventId: "evt_early" }, data: { nextAttemptAt: new Date(0) }
      });
      reconciliationClient.checkout.sessions.retrieve.mockResolvedValue({
        id: "cs_test_notRecorded", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
        ui_mode: "embedded_page", payment_status: "paid", currency: "usd", amount_total: 10000,
        automatic_tax: { enabled: true },
        metadata: { kuzushi_order_id: late.orderId, kuzushi_attempt_id: late.attemptId }
      });
      expect(await Promise.all([worker.processOne(), reconciler.reconcileAttempt(late.attemptId)])).toEqual([
        { state: "completed", observedStatus: "PAID" }, { observedStatus: "PAID", sessionStatus: "complete" }
      ]);
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: late.orderId } }))
        .toMatchObject({ initialPaymentStatus: "PAID", paidQuantity: 2 });
      expect(await prisma.stripeCheckoutEventResult.findUniqueOrThrow({ where: { eventId: "evt_early" } }))
        .toMatchObject({ orderId: late.orderId, observedStatus: "PAID" });
      const recoveryOrder = await checkout.begin(business.id, publicationId);
      if (!recoveryOrder) throw new Error("Expected a checkout for recovery");
      const recoveryClaim = await checkout.claim(business.id, recoveryOrder.attemptId);
      if (!recoveryClaim?.attempt.operationId) throw new Error("Expected a checkout recovery claim");
      expect(await checkout.recordSession(
        recoveryOrder.attemptId, recoveryClaim.attempt.operationId, "cs_test_recovery"
      )).toBe(true);
      const recoveryWorker = new CheckoutRecoveryWorker(
        checkoutRecoveryWork, checkoutReconciliation, reconciliationClient, business.id, connection.id
      );
      expect(await recoveryWorker.processOne()).toEqual({ state: "idle" });
      await prisma.checkoutRecoveryWork.update({
        where: { attemptId: recoveryOrder.attemptId }, data: { nextAttemptAt: new Date(0) }
      });
      expect(await checkoutRecoveryWork.claim(createdBusinessIds[0], connection.id, randomUUID())).toBeNull();
      const recoveryClaims = await Promise.all(Array.from({ length: 5 }, () =>
        checkoutRecoveryWork.claim(business.id, connection.id, randomUUID())
      ));
      const firstRecovery = recoveryClaims.find((item) => item !== null);
      expect(recoveryClaims.filter(Boolean)).toHaveLength(1);
      if (!firstRecovery) throw new Error("Expected recovery work");
      await prisma.checkoutRecoveryWork.update({
        where: { attemptId: recoveryOrder.attemptId }, data: { leaseUntil: new Date(0) }
      });
      const renewedRecovery = await checkoutRecoveryWork.claim(business.id, connection.id, randomUUID());
      if (!renewedRecovery) throw new Error("Expected an expired recovery lease to be reclaimed");
      expect(await checkoutRecoveryWork.complete(recoveryOrder.attemptId, firstRecovery.leaseToken)).toBe(false);
      expect(await checkoutRecoveryWork.retry(recoveryOrder.attemptId, renewedRecovery.leaseToken, "NOT_READY", 30)).toBe(true);
      expect(await recoveryWorker.processOne()).toEqual({ state: "idle" });
      await prisma.checkoutRecoveryWork.update({
        where: { attemptId: recoveryOrder.attemptId }, data: { nextAttemptAt: new Date(0) }
      });
      reconciliationClient.checkout.sessions.retrieve.mockResolvedValue({
        id: "cs_test_recovery", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
        ui_mode: "embedded_page", payment_status: "unpaid", currency: "usd", amount_total: 10000,
        automatic_tax: { enabled: true },
        metadata: { kuzushi_order_id: recoveryOrder.orderId, kuzushi_attempt_id: recoveryOrder.attemptId }
      });
      expect(await recoveryWorker.processOne()).toEqual({ state: "deferred" });
      expect(await recoveryWorker.processOne()).toEqual({ state: "idle" });
      expect(await prisma.checkoutRecoveryWork.findUniqueOrThrow({ where: { attemptId: recoveryOrder.attemptId } }))
        .toMatchObject({ status: "PENDING", lastError: null });
      await prisma.checkoutRecoveryWork.update({
        where: { attemptId: recoveryOrder.attemptId }, data: { nextAttemptAt: new Date(0) }
      });
      client.accounts.retrieveCurrent.mockRejectedValueOnce(new Error("Stripe unavailable"));
      expect(await recoveryWorker.processOne()).toEqual({ state: "retry", error: "STRIPE_UNAVAILABLE" });
      expect(await prisma.checkoutRecoveryWork.findUniqueOrThrow({ where: { attemptId: recoveryOrder.attemptId } }))
        .toMatchObject({ status: "PENDING", lastError: "STRIPE_UNAVAILABLE" });
      await prisma.checkoutRecoveryWork.update({
        where: { attemptId: recoveryOrder.attemptId }, data: { nextAttemptAt: new Date(0) }
      });
      reconciliationClient.checkout.sessions.retrieve.mockResolvedValue({
        id: "cs_test_recovery", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
        ui_mode: "embedded_page", payment_status: "paid", currency: "usd", amount_total: 10000,
        automatic_tax: { enabled: true },
        metadata: { kuzushi_order_id: recoveryOrder.orderId, kuzushi_attempt_id: recoveryOrder.attemptId }
      });
      expect(await recoveryWorker.processOne()).toEqual({ state: "completed", observedStatus: "PAID" });
      expect(await prisma.checkoutRecoveryWork.findUniqueOrThrow({ where: { attemptId: recoveryOrder.attemptId } }))
        .toMatchObject({ status: "DONE", lastError: null });
      expect(await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: recoveryOrder.orderId } }))
        .toMatchObject({ initialPaymentStatus: "PAID", paidQuantity: 2 });
      expect(await prisma.stripeCheckoutEvent.count({ where: { sessionId: "cs_test_recovery" } })).toBe(0);
      const webhookApp = createApp({
        repository, store: new session.MemoryStore(), secret: "integration-test-secret-at-least-32-characters",
        origin, production: false, checkoutWebhook: new CheckoutWebhookReceiver({
          resolve: async (id) => id === connection.id ? {
            binding: {
              connectionId: connection.id, businessId: business.id, accountId: "acct_publicationflow",
              mode: "TEST", source: "direct"
            }, secrets: [secret]
          } : null
        }, checkoutWebhook)
      });
      const httpBody = JSON.stringify({
        ...event, id: "evt_http", data: { object: { id: "cs_test_recovery", object: "checkout.session" } }
      });
      const httpSignature = Stripe.webhooks.generateTestHeaderString({ payload: httpBody, secret });
      for (let count = 0; count < 2; count++) {
        await request(webhookApp).post(`/api/stripe/webhooks/checkout/${connection.id}`)
          .set("Content-Type", "application/json").set("Stripe-Signature", httpSignature).send(httpBody).expect(204);
      }
      expect(await prisma.stripeCheckoutEventWork.count({ where: { eventId: "evt_http" } })).toBe(1);
      await prisma.checkoutRecoveryWork.update({
        where: { attemptId: started.attemptId }, data: { nextAttemptAt: new Date(0) }
      });
      client.accounts.retrieveCurrent.mockClear();
      expect(await recoveryWorker.processOne()).toEqual({ state: "completed", observedStatus: "PAID" });
      expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
      await expect(prisma.checkoutOrder.update({
        where: { id: started.orderId }, data: { initialPaymentStatus: "UNPAID", paidQuantity: null }
      })).rejects.toThrow();
      const conflict = JSON.stringify({ ...event, data: { object: { id: "cs_test_other", object: "checkout.session" } } });
      await expect(inbox.accept(Buffer.from(conflict), Stripe.webhooks.generateTestHeaderString({ payload: conflict, secret })))
        .rejects.toThrow("Conflicting checkout webhook event");
      const wrongBusinessInbox = new CheckoutWebhookInbox({
        connectionId: connection.id, businessId: createdBusinessIds[0], accountId: "acct_publicationflow",
        mode: "TEST", source: "direct"
      }, [secret], checkoutWebhook);
      const wrongBusinessBody = JSON.stringify({ ...event, id: "evt_wrongBusiness" });
      await expect(wrongBusinessInbox.accept(
        Buffer.from(wrongBusinessBody), Stripe.webhooks.generateTestHeaderString({ payload: wrongBusinessBody, secret })
      )).rejects.toThrow("Checkout webhook connection unavailable");
      expect(await prisma.stripeCheckoutEvent.findUnique({ where: { id: "evt_wrongBusiness" } })).toBeNull();
      await expect(prisma.stripeCheckoutEvent.update({
        where: { id: event.id }, data: { sessionId: "cs_test_other" }
      })).rejects.toThrow();
    } finally {
      await prisma.auditEvent.deleteMany({ where: { businessId: business.id, action: "CHECKOUT_PAYMENT_RECONCILED" } });
      await prisma.stripeCheckoutEventResult.deleteMany({ where: { order: { publication: { businessId: business.id } } } });
      await prisma.stripeCheckoutEventWork.deleteMany({ where: { event: { businessId: business.id } } });
      await prisma.stripeCheckoutEvent.deleteMany({ where: { businessId: business.id } });
      await prisma.checkoutRecoveryWork.deleteMany({ where: { attempt: { order: { publication: { businessId: business.id } } } } });
      await prisma.checkoutAttempt.deleteMany({ where: { order: { publication: { businessId: business.id } } } });
      await prisma.checkoutOrder.deleteMany({ where: { publication: { businessId: business.id } } });
      await prisma.stripePublication.deleteMany({ where: { businessId: business.id } });
      await prisma.business.delete({ where: { id: business.id } });
      createdBusinessIds.splice(createdBusinessIds.indexOf(business.id), 1);
    }
  });

  it("serializes draft writes with session revocation and rejects stale actors", async () => {
    const user = await prisma.user.create({
      data: { email: email("draft-revoked"), passwordHash: "unused" }
    });
    const business = await prisma.business.create({
      data: { name: "Draft revocation test", memberships: { create: { userId: user.id } } }
    });
    createdBusinessIds.push(business.id);
    const input = {
      name: "Before", description: "", kind: "SERVICE" as const, amountCents: 5000,
      billing: "ONE_TIME" as const, interval: null
    };
    const draft = await repository.createProductDraft(user, business.id, input);
    if (!draft) throw new Error("Expected an authorized draft");
    const client = await pool.connect();
    let outcomes: Promise<PromiseSettledResult<unknown>[]> | undefined;
    let settledBeforeCommit = false;
    let committed = false;
    try {
      await client.query("BEGIN");
      await client.query('UPDATE "User" SET "sessionVersion" = "sessionVersion" + 1 WHERE "id" = $1', [user.id]);
      outcomes = Promise.allSettled([
        repository.createProductDraft(user, business.id, input),
        repository.updateProductDraft(user, business.id, draft.id, { ...input, name: "After" })
      ]);
      settledBeforeCommit = await Promise.race([
        outcomes.then(() => true),
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 200))
      ]);
      await client.query("COMMIT");
      committed = true;
    } finally {
      if (!committed) await client.query("ROLLBACK");
      client.release();
    }
    expect(settledBeforeCommit).toBe(false);
    const results = await outcomes;
    expect(results).toHaveLength(2);
    for (const result of results ?? []) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") expect(result.reason).toBeInstanceOf(AuthorizationChangedError);
    }
    expect(await repository.listProductDrafts(user, business.id)).toEqual([]);
    expect(await prisma.productDraft.findMany({ where: { businessId: business.id } }))
      .toMatchObject([{ id: draft.id, name: "Before" }]);
    expect(await prisma.auditEvent.count({ where: { businessId: business.id, action: "PRODUCT_DRAFT_UPDATED" } })).toBe(0);
  }, 30000);

  it("scopes live Checkout to the DNS-verified revision and a ready OAuth connection", async () => {
    const owner = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const business = await prisma.business.create({ data: { name: "Live Checkout test",
      memberships: { create: { userId: owner.id } } } });
    createdBusinessIds.push(business.id);
    try {
      expect(await bindLiveOAuth(owner, business.id, "acct_LiveCheckout", {
        secretId: `kp-stripe-oauth-live-${"c".repeat(32)}`, version: "1"
      })).toBe(true);
      const draft = await repository.createProductDraft(owner, business.id, { name: "Class", description: "", kind: "SERVICE",
        amountCents: 5000, billing: "RECURRING", interval: "MONTH" });
      const published = draft && await publication.begin(owner, business.id, draft.id, "LIVE");
      if (!published) throw new Error("Expected a live publication");
      const product = await publication.claimProduct(published.id);
      if (!product?.operationId) throw new Error("Expected product claim");
      expect(await publication.recordProduct(published.id, product.operationId, "prod_LiveCheckout")).toBe(true);
      const price = await publication.claimPrice(published.id);
      if (!price?.operationId) throw new Error("Expected price claim");
      expect(await publication.recordPrice(published.id, price.operationId, "price_LiveCheckout")).toBe(true);

      const origin = "https://live-store.example";
      const returnUrl = `${origin}/return?session_id={CHECKOUT_SESSION_ID}`;
      const proposed = await storefrontProposal.save(owner, business.id, { origin, returnUrl });
      if (!proposed) throw new Error("Expected a storefront proposal");
      const setup = { mode: "LIVE" as const, origin, revision: proposed.revision,
        requestId: randomUUID(), connectionId: published.connectionId };
      await storefrontProposal.approveTest(admin, business.id, proposed.revision);
      expect(await checkout.begin(business.id, published.id, setup)).toBeNull();
      resolveStorefrontTxt.mockResolvedValueOnce([[`kuzushi-pay-verification=${proposed.revision}`]]);
      expect(await storefrontProposal.verify(owner, business.id, proposed.revision)).toBeTruthy();
      expect(await checkout.begin(business.id, published.id, { ...setup, connectionId: randomUUID() })).toBeNull();
      const started = await checkout.begin(business.id, published.id, setup);
      if (!started) throw new Error("Expected a live checkout attempt");
      expect(await checkout.begin(business.id, published.id, setup)).toBeNull();

      const rotation = await oauthRotation.claim(business.id, "LIVE", "d".repeat(32));
      if (!rotation) throw new Error("Expected a refresh claim");
      expect(await checkout.claim(business.id, started.attemptId, setup)).toBeNull();
      expect(await oauthRotation.release(rotation)).toBe(true);
      const claimed = await checkout.claim(business.id, started.attemptId, setup);
      if (!claimed?.attempt.operationId) throw new Error("Expected a live checkout claim");
      expect(claimed.storefront).toEqual({ origin, returnUrl });
      expect(await checkout.recordSession(started.attemptId, claimed.attempt.operationId, "cs_live_Checkout")).toBe(true);
      expect(await prisma.checkoutRecoveryWork.findUnique({ where: { attemptId: started.attemptId } })).toBeTruthy();

      const newerSetup = { ...setup, requestId: randomUUID() };
      const pending = await checkout.begin(business.id, published.id, newerSetup);
      if (!pending) throw new Error("Expected a pending checkout attempt");
      await storefrontProposal.save(owner, business.id, { origin, returnUrl: `${origin}/changed?session_id={CHECKOUT_SESSION_ID}` });
      expect(await checkout.claim(business.id, pending.attemptId, newerSetup)).toBeNull();
    } finally {
      await prisma.checkoutRecoveryWork.deleteMany({ where: { attempt: { order: { publication: { businessId: business.id } } } } });
      await prisma.checkoutAttempt.deleteMany({ where: { order: { publication: { businessId: business.id } } } });
      await prisma.checkoutOrder.deleteMany({ where: { publication: { businessId: business.id } } });
      await prisma.stripePublication.deleteMany({ where: { businessId: business.id } });
      await prisma.business.delete({ where: { id: business.id } });
      createdBusinessIds.splice(createdBusinessIds.indexOf(business.id), 1);
    }
  });

  it("allows only the live connection's owner to reconnect the same Stripe account", async () => {
    const owner = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const other = await prisma.user.findUniqueOrThrow({ where: { email: email("b") } });
    const businessId = createdBusinessIds[0];
    const accountId = "acct_LiveReconnect";
    const reference = { secretId: `kp-stripe-oauth-live-${"a".repeat(32)}`, version: "1" };
    expect(await bindLiveOAuth(owner, businessId, accountId, reference)).toBe(true);
    const claim = await oauthRotation.claim(businessId, "LIVE", "a".repeat(32));
    if (!claim) throw new Error("Expected a live OAuth refresh claim");
    try {
      expect(await liveOAuthState.status(owner, businessId)).toBe("unavailable");
      expect(await oauthRotation.requireReconnect(claim)).toBe(true);
      expect(await liveOAuthState.status(owner, businessId)).toBe("reconnect_required");
      const replacement = { ...reference, version: "2" };
      expect(await bindLiveOAuth(other, businessId, accountId, replacement)).toBe(false);
      expect(await bindLiveOAuth(owner, businessId, "acct_other", replacement)).toBe(false);
      expect(await bindLiveOAuth(owner, businessId, accountId, reference)).toBe(false);
      expect(await bindLiveOAuth(owner, businessId, accountId, replacement)).toBe(true);
      expect(await bindLiveOAuth(owner, businessId, accountId, { ...reference, version: "3" })).toBe(false);
      expect(await liveOAuthState.status(owner, businessId)).toBe("connected");
      expect(await oauthRotation.claim(businessId, "LIVE", "b".repeat(32), reference)).toBeNull();
      expect(await prisma.stripeOAuthCredential.findUniqueOrThrow({ where: { connectionId: claim.connectionId } }))
        .toMatchObject({ version: "2", status: "READY", operationId: null });
    } finally {
      await prisma.stripeConnection.delete({ where: { id: claim.connectionId } });
    }
  });

  it("serializes OAuth refresh claims and refuses stale or disconnected updates", async () => {
    const connection = await prisma.stripeConnection.create({
      data: {
        businessId: createdBusinessIds[0], mode: "TEST", status: "VERIFIED", stripeAccountId: "acct_rotation",
        oauthCredential: { create: { secretId: `kp-stripe-oauth-test-${"a".repeat(32)}`, version: "1" } }
      }
    });
    try {
      expect(await oauthRotation.claim(createdBusinessIds[1], "TEST", "f".repeat(32))).toBeNull();
      expect(await oauthRotation.claim(createdBusinessIds[0], "LIVE", "f".repeat(32))).toBeNull();
      const results = await Promise.all([
        oauthRotation.claim(createdBusinessIds[0], "TEST", "1".repeat(32)),
        oauthRotation.claim(createdBusinessIds[0], "TEST", "2".repeat(32))
      ]);
      const claims = results.filter((result) => result !== null);
      expect(claims).toHaveLength(1);
      const claim = claims[0];
      expect(await oauthRotation.complete({ ...claim, operationId: "3".repeat(32) }, "2")).toBe(false);
      expect(await oauthRotation.complete(claim, "2")).toBe(true);
      expect(await prisma.stripeOAuthCredential.findUniqueOrThrow({ where: { connectionId: connection.id } }))
        .toMatchObject({ version: "2", status: "READY", operationId: null });
      const next = await oauthRotation.claim(createdBusinessIds[0], "TEST", "4".repeat(32));
      if (!next) throw new Error("Expected a second claim");
      await expect(prisma.stripeOAuthCredential.update({
        where: { connectionId: connection.id }, data: { operationId: null }
      })).rejects.toThrow();
      await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "DISCONNECTED" } });
      expect(await oauthRotation.complete(next, "3")).toBe(false);
      expect(await oauthRotation.requireReconnect(next)).toBe(true);
      expect(await oauthRotation.claim(createdBusinessIds[0], "TEST", "5".repeat(32))).toBeNull();
    } finally {
      await prisma.stripeConnection.delete({ where: { id: connection.id } });
    }
  });

  it("integrates staging callback and mocked exchange with scoped business and fail-closed checks", async () => {
    const stagingOrigin = "https://staging.example.com";
    const oauth = new SandboxOAuthService(repository, oauthAttempts, {
      installUrl: "https://marketplace.stripe.com/oauth/v2/authorize?client_id=client_test_example",
      redirectUri: `${stagingOrigin}/api/stripe/oauth/sandbox/callback`,
      businessId: createdBusinessIds[0]
    }, "integration-test-secret-at-least-32-characters");
    const readCredential = vi.fn().mockResolvedValue(Buffer.from("sk_test_fixture"));
    const exchange = vi.fn().mockResolvedValue({
      stripe_user_id: "acct_expected", livemode: false,
      access_token: "sensitive_token_marker", refresh_token: "sensitive_token_marker"
    });
    const service = new SandboxIdentityExchange("staging", oauth, readCredential, "acct_expected", exchange);
    const stagingApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin: stagingOrigin, production: true, loginRateLimitStore,
      staging: true, sandboxOAuth: oauth, sandboxExchange: service
    });
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await request(stagingApp).get("/api/me").expect(403);
      const login = await request(stagingApp).post("/api/login").set("Origin", stagingOrigin)
        .set("X-Forwarded-Proto", "https").send({ email: email("admin"), password }).expect(200);
      const header = firstCookie(login.headers);
      expect(header).toContain("Secure");
      expect(header).toContain("HttpOnly");
      expect(header).toContain("SameSite=Lax");
      const cookie = header.split(";")[0];
      const path = `/api/businesses/${createdBusinessIds[0]}/stripe/oauth/sandbox`;
      const start = () => request(stagingApp).post(path).set("Cookie", cookie)
        .set("Origin", stagingOrigin).set("X-Forwarded-Proto", "https").send({});
      await request(stagingApp).post(path).set("Cookie", cookie).set("Origin", "https://evil.example")
        .set("X-Forwarded-Proto", "https").send({}).expect(403);
      await request(stagingApp).post(`/api/businesses/${createdBusinessIds[1]}/stripe/oauth/sandbox`)
        .set("Cookie", cookie).set("Origin", stagingOrigin).set("X-Forwarded-Proto", "https").send({}).expect(404);
      const createState = async () => {
        const response = await start().expect(200);
        const state = new URL(response.body.authorizationUrl).searchParams.get("state");
        if (!state) throw new Error("Missing OAuth state");
        return state;
      };
      const callback = (state: string, browserCookie = cookie) => request(stagingApp)
        .get("/api/stripe/oauth/sandbox/callback").set("Cookie", browserCookie)
        .set("X-Forwarded-Proto", "https").query({ state, code: "sensitive_code_marker" });
      const unscopedOAuth = new SandboxOAuthService(repository, oauthAttempts, {
        installUrl: "https://marketplace.stripe.com/oauth/v2/authorize?client_id=client_test_example",
        redirectUri: `${stagingOrigin}/api/stripe/oauth/sandbox/callback`
      }, "integration-test-secret-at-least-32-characters");
      const unscopedApp = createApp({
        repository, store, secret: "integration-test-secret-at-least-32-characters",
        origin: stagingOrigin, production: true, loginRateLimitStore, staging: true, sandboxOAuth: unscopedOAuth
      });
      const other = await request(unscopedApp).post(`/api/businesses/${createdBusinessIds[1]}/stripe/oauth/sandbox`)
        .set("Cookie", cookie).set("Origin", stagingOrigin).set("X-Forwarded-Proto", "https").send({}).expect(200);
      const otherState = new URL(other.body.authorizationUrl).searchParams.get("state");
      if (!otherState) throw new Error("Missing OAuth state");
      expect((await callback(otherState)).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      expect(exchange).not.toHaveBeenCalled();
      await prisma.stripeOAuthAttempt.deleteMany({ where: { businessId: createdBusinessIds[1] } });
      const state = await createState();
      expect((await callback(state, "kuzushi.sid=invalid")).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      const success = await callback(state);
      expect(success.headers.location).toBe(`${stagingOrigin}/?stripe_oauth=identity_verified`);
      expect(success.headers["cache-control"]).toContain("no-store");
      expect(success.headers["referrer-policy"]).toBe("no-referrer");
      expect((await callback(state)).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      for (const response of [
        { stripe_user_id: "acct_other", livemode: false, access_token: "mock", refresh_token: "mock" },
        { stripe_user_id: "acct_expected", livemode: true, access_token: "mock", refresh_token: "mock" }
      ]) {
        const nextState = await createState();
        exchange.mockResolvedValueOnce(response);
        expect((await callback(nextState)).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      }
      const failedState = await createState();
      exchange.mockRejectedValueOnce(new Error("sensitive_token_marker"));
      expect((await callback(failedState)).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      const canceledState = await createState();
      const callsBeforeCancel = exchange.mock.calls.length;
      const canceled = await request(stagingApp).get("/api/stripe/oauth/sandbox/callback")
        .set("Cookie", cookie).set("X-Forwarded-Proto", "https")
        .query({ state: canceledState, error: "access_denied" });
      expect(canceled.headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      expect((await callback(canceledState)).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      expect(exchange).toHaveBeenCalledTimes(callsBeforeCancel);
      const expiredState = await createState();
      await prisma.stripeOAuthAttempt.updateMany({
        where: { businessId: createdBusinessIds[0], active: true }, data: { expiresAt: new Date(0) }
      });
      expect((await callback(expiredState)).headers.location).toBe(`${stagingOrigin}/?stripe_oauth=failed`);
      const text = JSON.stringify({ headers: success.headers, body: success.text, logs: logs.mock.calls });
      expect(text).not.toContain("sensitive_code_marker");
      expect(text).not.toContain("sensitive_token_marker");
      expect(await prisma.stripeConnection.count({ where: { businessId: createdBusinessIds[0] } })).toBe(0);
    } finally {
      logs.mockRestore();
      await prisma.stripeOAuthAttempt.deleteMany({ where: { businessId: createdBusinessIds[0] } });
    }
  }, 30000);

  it("allows only one mocked exchange for a database-backed OAuth attempt", async () => {
    const oauth = new SandboxOAuthService(repository, oauthAttempts, {
      installUrl: "https://marketplace.stripe.com/oauth/v2/authorize?client_id=client_test_example",
      redirectUri: "https://sandbox.example.com/api/stripe/oauth/sandbox/callback"
    }, "integration-test-secret-at-least-32-characters");
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const sessionData = { userId: user.id, authenticatedAt: Date.now(), authVersion: user.sessionVersion };
    const initiated = await oauth.initiate(sessionData, "session", createdBusinessIds[0]);
    if (!("url" in initiated)) throw new Error("OAuth initiation failed");
    const state = new URL(initiated.url).searchParams.get("state");
    if (!state) throw new Error("Missing OAuth state");
    const readCredential = vi.fn().mockResolvedValue(Buffer.from("sk_test_fixture"));
    const exchange = vi.fn().mockResolvedValue({
      stripe_user_id: "acct_expected", livemode: false,
      access_token: "mock_access", refresh_token: "mock_refresh"
    });
    const service = new SandboxIdentityExchange("test", oauth, readCredential, "acct_expected", exchange);
    const results = await Promise.all([
      service.verify(sessionData, "session", state, "code_test"),
      service.verify(sessionData, "session", state, "code_test")
    ]);
    expect(results).toContainEqual({ ok: true, accountId: "acct_expected" });
    expect(results).toContainEqual({ ok: false, error: "INVALID_STATE" });
    expect(readCredential).toHaveBeenCalledOnce();
    expect(exchange).toHaveBeenCalledOnce();
    expect(await prisma.stripeConnection.count({ where: { businessId: createdBusinessIds[0] } })).toBe(0);
    await prisma.stripeOAuthAttempt.deleteMany({ where: { businessId: createdBusinessIds[0] } });
  }, 30000);

  it("validates OAuth callbacks once, binds sessions and businesses, and rejects expiry and races", async () => {
    const oauth = new SandboxOAuthService(repository, oauthAttempts, {
      installUrl: "https://marketplace.stripe.com/oauth/v2/authorize?client_id=client_test_example",
      redirectUri: "https://sandbox.example.com/api/stripe/oauth/sandbox/callback"
    }, "integration-test-secret-at-least-32-characters");
    const oauthApp = createApp({ repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, sandboxOAuth: oauth });
    const makeAgent = async (role: string) => {
      const response = await request(oauthApp).post("/api/login").set("Origin", origin).set("X-Forwarded-Proto", "https")
        .send({ email: email(role), password }).expect(200);
      const header = firstCookie(response.headers);
      expect(header).toContain("Secure");
      return header.split(";")[0];
    };
    const a = await makeAgent("a");
    const otherSession = await makeAgent("a");
    const b = await makeAgent("b");
    const start = () => request(oauthApp).post(`/api/businesses/${createdBusinessIds[0]}/stripe/oauth/sandbox`)
      .set("Cookie", a).set("Origin", origin).set("X-Forwarded-Proto", "https").send({});
    await request(oauthApp).post(`/api/businesses/${createdBusinessIds[0]}/stripe/oauth/sandbox`).set("Cookie", b)
      .set("Origin", origin).set("X-Forwarded-Proto", "https").send({}).expect(404);
    await request(oauthApp).post(`/api/businesses/${createdBusinessIds[0]}/stripe/oauth/sandbox`)
      .set("Origin", origin).set("X-Forwarded-Proto", "https").send({}).expect(401);
    const [first, second] = await Promise.all([start(), start()]);
    expect([first.status, second.status].sort()).toEqual([200, 409]);
    const url = new URL((first.status === 200 ? first : second).body.authorizationUrl);
    const state = url.searchParams.get("state");
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = await prisma.stripeOAuthAttempt.findFirstOrThrow({ where: { businessId: createdBusinessIds[0], active: true } });
    expect(stored.environment).toBe("SANDBOX");
    expect(JSON.stringify(stored)).not.toContain(state);
    expect(stored.stateHash).toMatch(/^[a-f0-9]{64}$/);
    expect(stored.sessionHash).toMatch(/^[a-f0-9]{64}$/);
    expect(url.searchParams.get("redirect_uri")).toBe("https://sandbox.example.com/api/stripe/oauth/sandbox/callback");
    const callback = (cookie: string, token: string) => request(oauthApp).get("/api/stripe/oauth/sandbox/callback")
      .set("Cookie", cookie).set("X-Forwarded-Proto", "https").query({ state: token, code: "harmless_code_marker" });
    expect((await callback("kuzushi.sid=invalid", state!)).headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    expect((await callback(b, state!)).headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    expect((await callback(a, "invalid-state")).headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    const swapped = await callback(otherSession, state!);
    expect(swapped.headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    const [one, two] = await Promise.all([callback(a, state!), callback(a, state!)]);
    expect([one.headers.location, two.headers.location].sort()).toEqual([
      `${origin}/?stripe_oauth=failed`, `${origin}/?stripe_oauth=validated`
    ]);
    expect(one.headers["cache-control"]).toContain("no-store");
    expect(one.headers["referrer-policy"]).toBe("no-referrer");
    expect(JSON.stringify({ one: one.text, two: two.text, headers: one.headers })).not.toContain("harmless_code_marker");
    expect(JSON.stringify(await prisma.stripeOAuthAttempt.findUniqueOrThrow({ where: { id: stored.id } })))
      .not.toContain("harmless_code_marker");
    expect((await callback(a, state!)).headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    const expired = await start();
    expect(expired.status).toBe(200);
    const expiredState = new URL(expired.body.authorizationUrl).searchParams.get("state")!;
    await prisma.stripeOAuthAttempt.updateMany({
      where: { businessId: createdBusinessIds[0], active: true }, data: { expiresAt: new Date(0) }
    });
    expect((await callback(a, expiredState)).headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    const revoked = await start();
    expect(revoked.status).toBe(200);
    const revokedState = new URL(revoked.body.authorizationUrl).searchParams.get("state")!;
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    await prisma.membership.delete({ where: { userId_businessId: { userId: user.id, businessId: createdBusinessIds[0] } } });
    try {
      expect((await callback(a, revokedState)).headers.location).toBe(`${origin}/?stripe_oauth=failed`);
    } finally {
      await prisma.membership.create({ data: { userId: user.id, businessId: createdBusinessIds[0] } });
      await prisma.stripeOAuthAttempt.deleteMany({ where: { businessId: createdBusinessIds[0] } });
    }
  }, 30000);

  it("scopes test credential lookup by business, user, mode and connection status", async () => {
    const a = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const b = await prisma.user.findUniqueOrThrow({ where: { email: email("b") } });
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const secretId = `kp-stripe-test-${id.replaceAll("-", "")}`;
    const connection = await prisma.stripeConnection.create({
      data: {
        businessId: createdBusinessIds[0], mode: "TEST", status: "VERIFIED",
        stripeAccountId: "acct_testfixture", credential: { create: { secretId, version: "1" } }
      }
    });
    expect(await checkoutRecoveryBindings.find(createdBusinessIds[0], connection.id, "TEST")).toEqual({
      businessId: createdBusinessIds[0], connectionId: connection.id, accountId: "acct_testfixture",
      mode: "TEST", reference: { secretId, version: "1" }
    });
    expect(await checkoutRecoveryBindings.find(createdBusinessIds[1], connection.id, "TEST")).toBeNull();
    expect(await checkoutRecoveryBindings.find(createdBusinessIds[0], connection.id, "LIVE")).toBeNull();
    const accessVersion = vi.fn().mockResolvedValue(Buffer.from("harmless"));
    const service = new BusinessCredentialService(repository, {
      accessVersion, addVersion: vi.fn(), disableVersion: vi.fn()
    });
    const now = Date.now();
    const sessionFor = (userId: string) => ({ userId, authenticatedAt: now, authVersion: 0 });
    expect(await repository.findVerifiedTestCredential(a, createdBusinessIds[0])).toEqual({ secretId, version: "1" });
    expect(await repository.findVerifiedTestCredential(b, createdBusinessIds[0])).toBeNull();
    await expect(service.accessTestCredential(sessionFor(b.id), createdBusinessIds[0])).rejects.toThrow("Credential unavailable");
    expect(accessVersion).not.toHaveBeenCalled();
    await service.accessTestCredential(sessionFor(a.id), createdBusinessIds[0]);
    await service.accessTestCredential(sessionFor(admin.id), createdBusinessIds[0]);
    expect(accessVersion).toHaveBeenCalledTimes(2);
    await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "DISCONNECTED" } });
    expect(await checkoutRecoveryBindings.find(createdBusinessIds[0], connection.id, "TEST")).toBeNull();
    await expect(service.accessTestCredential(sessionFor(a.id), createdBusinessIds[0])).rejects.toThrow("Credential unavailable");
    await prisma.stripeConnection.update({ where: { id: connection.id }, data: { status: "PENDING_VERIFICATION" } });
    expect(await checkoutRecoveryBindings.find(createdBusinessIds[0], connection.id, "TEST")).toBeNull();
    expect(await repository.findVerifiedTestCredential(a, createdBusinessIds[0])).toBeNull();
    await prisma.stripeConnection.delete({ where: { id: connection.id } });
    const liveConnection = await prisma.stripeConnection.create({
      data: {
        businessId: createdBusinessIds[0], mode: "LIVE", status: "VERIFIED", stripeAccountId: "acct_livefixture",
        credential: { create: { secretId: `kp-stripe-live-${id.replaceAll("-", "")}`, version: "1" } }
      }
    });
    expect(await checkoutRecoveryBindings.find(createdBusinessIds[0], liveConnection.id, "LIVE")).toMatchObject({
      businessId: createdBusinessIds[0], connectionId: liveConnection.id, mode: "LIVE", accountId: "acct_livefixture"
    });
    expect(await repository.findVerifiedTestCredential(a, createdBusinessIds[0])).toBeNull();
    expect(accessVersion).toHaveBeenCalledTimes(2);
    await prisma.stripeConnection.deleteMany({ where: { businessId: createdBusinessIds[0], mode: "LIVE" } });
  }, 30000);

  it("rejects secret-like data and unpinned versions in credential reference fields", async () => {
    const connection = await prisma.stripeConnection.create({
      data: { businessId: createdBusinessIds[0], mode: "TEST" }
    });
    await expect(prisma.stripeCredentialReference.create({
      data: { connectionId: connection.id, secretId: "rk_test_not_a_reference", version: "1" }
    })).rejects.toThrow();
    await expect(prisma.stripeCredentialReference.create({
      data: { connectionId: connection.id, secretId: `kp-stripe-test-${id.replaceAll("-", "")}`, version: "latest" }
    })).rejects.toThrow();
    await prisma.stripeConnection.delete({ where: { id: connection.id } });
  }, 30000);

  it("prevents duplicate account bindings per mode and verified connections without an account", async () => {
    await expect(prisma.stripeConnection.create({
      data: { businessId: createdBusinessIds[0], mode: "TEST", status: "VERIFIED" }
    })).rejects.toThrow();
    const connection = await prisma.stripeConnection.create({
      data: { businessId: createdBusinessIds[0], mode: "TEST", stripeAccountId: "acct_unique" }
    });
    await expect(prisma.stripeConnection.create({
      data: { businessId: createdBusinessIds[1], mode: "TEST", stripeAccountId: "acct_unique" }
    })).rejects.toThrow();
    const otherMode = await prisma.stripeConnection.create({
      data: { businessId: createdBusinessIds[1], mode: "LIVE", stripeAccountId: "acct_unique" }
    });
    await prisma.stripeConnection.deleteMany({ where: { id: { in: [connection.id, otherMode.id] } } });
  }, 30000);
  it("authenticates, persists a session across app instances, then invalidates it on logout", async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    const previousEvents = await prisma.auditEvent.count({ where: { actorId: user.id } });
    await request(app).post("/api/login").set("Origin", origin).send({ email: email("a"), password: "wrong" }).expect(401);
    const { agent, cookie, header } = await login("a");
    const newEvents = await prisma.auditEvent.findMany({
      where: { actorId: user.id }, orderBy: { createdAt: "asc" }, skip: previousEvents,
      select: { action: true, actorId: true, targetId: true, businessId: true }
    });
    expect(newEvents).toEqual([
      { action: "LOGIN_FAILED", actorId: user.id, targetId: user.id, businessId: null },
      { action: "LOGIN_SUCCEEDED", actorId: user.id, targetId: user.id, businessId: null }
    ]);
    expect(header).toContain("HttpOnly");
    expect(header).toContain("SameSite=Lax");
    expect(header).not.toContain("Secure");
    expect(header).toMatch(/Expires=/);
    const secondStore = new PgStore({ pool, tableName: "session", pruneSessionInterval: false });
    const secondApp = createApp({ repository, store: secondStore, secret: "integration-test-secret-at-least-32-characters", origin, production: false });
    expect((await request(secondApp).get("/api/me").set("Cookie", cookie).expect(200)).body.user.email).toBe(email("a"));
    await agent.post("/api/logout").set("Origin", origin).send({}).expect(200);
    await request(secondApp).get("/api/me").set("Cookie", cookie).expect(401);
  }, 30000);

  it("regenerates the session on a new login and rejects the old cookie", async () => {
    const { agent, cookie } = await login("a");
    const response = await agent.post("/api/login").set("Origin", origin).send({ email: email("b"), password }).expect(200);
    const newCookie = firstCookie(response.headers).split(";")[0];
    expect(newCookie).not.toBe(cookie);
    await request(app).get("/api/me").set("Cookie", cookie).expect(401);
    expect((await agent.get("/api/me").expect(200)).body.user.email).toBe(email("b"));
  }, 30000);

  it("enforces an absolute server-side lifetime despite store activity", async () => {
    const { agent } = await login("a");
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    await pool.query(
      `UPDATE "session" SET sess = jsonb_set(sess::jsonb, '{authenticatedAt}', to_jsonb($1::bigint))::json WHERE sess->>'userId' = $2`,
      [Date.now() - 8 * 60 * 60 * 1000 - 1000, user.id]
    );
    await agent.get("/api/me").expect(401);
    await agent.post("/api/login").set("Origin", origin).send({ email: email("a"), password }).expect(200);
    await agent.get("/api/me").expect(200);
  }, 30000);

  it("prevents owners from accessing or listing another business and denies admin operations", async () => {
    const ownerA = await login("a");
    const ownerB = await login("b");
    expect((await ownerA.agent.get("/api/businesses").expect(200)).body.businesses.map((b: { id: string }) => b.id)).toEqual([createdBusinessIds[0]]);
    expect((await ownerB.agent.get("/api/businesses").expect(200)).body.businesses.map((b: { id: string }) => b.id)).toEqual([createdBusinessIds[1]]);
    await ownerA.agent.get(`/api/businesses/${createdBusinessIds[0]}`).expect(200);
    await ownerA.agent.get(`/api/businesses/${createdBusinessIds[1]}`).expect(404);
    await ownerB.agent.get(`/api/businesses/${createdBusinessIds[0]}`).expect(404);
    await ownerA.agent.get(`/api/businesses/${randomUUID()}`).expect(404);
    await ownerA.agent.post("/api/businesses").set("Origin", origin).send({ name: "Denied", email: email("new"), password }).expect(403);
  }, 30000);

  it("allows administrators to access and provision businesses without changing existing owners", async () => {
    const { agent } = await login("admin");
    await agent.get(`/api/businesses/${createdBusinessIds[1]}`).expect(200);
    const response = await agent.post("/api/businesses").set("Origin", origin).send({ name: "New", email: email("new"), password }).expect(201);
    createdBusinessIds.push(response.body.business.id);
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const newOwner = await prisma.user.findUniqueOrThrow({ where: { email: email("new") } });
    expect(await prisma.auditEvent.findFirst({
      where: { businessId: response.body.business.id, action: "BUSINESS_CREATED" }
    })).toMatchObject({ actorId: admin.id, targetId: newOwner.id });
    await agent.post("/api/businesses").set("Origin", origin).send({ name: "Duplicate", email: email("a"), password }).expect(409);
    const owner = await login("new");
    expect((await owner.agent.get("/api/businesses").expect(200)).body.businesses).toEqual([{ id: response.body.business.id, name: "New" }]);
  }, 30000);

  it("creates only one owner and business for concurrent provisioning of the same email", async () => {
    const admin = await prisma.user.findUniqueOrThrow({ where: { email: email("admin") } });
    const results = await Promise.allSettled([
      repository.createBusinessWithOwner(admin, "Race one", email("race"), admin.passwordHash),
      repository.createBusinessWithOwner(admin, "Race two", email("race"), admin.passwordHash)
    ]);
    const successes = results.filter((result) => result.status === "fulfilled");
    const failures = results.filter((result) => result.status === "rejected");
    for (const result of successes) createdBusinessIds.push(result.value.id);
    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(1);
    expect(failures[0].reason).toBeInstanceOf(EmailInUseError);
    expect(await prisma.user.count({ where: { email: email("race") } })).toBe(1);
    expect(await prisma.auditEvent.count({
      where: { actorId: admin.id, businessId: successes[0].value.id, action: "BUSINESS_CREATED" }
    })).toBe(1);
  }, 30000);

  it("rechecks administrator permissions and session version when provisioning", async () => {
    const admin = await prisma.user.create({
      data: { email: email("stale-admin"), passwordHash: "fixture", role: "ADMIN" }
    });
    await prisma.user.update({ where: { id: admin.id }, data: { sessionVersion: { increment: 1 } } });
    await expect(repository.createBusinessWithOwner(admin, "Denied", email("denied-owner"), "fixture"))
      .rejects.toBeInstanceOf(AuthorizationChangedError);
    const owner = await prisma.user.findUniqueOrThrow({ where: { email: email("a") } });
    await expect(repository.createBusinessWithOwner(owner, "Denied", email("denied-owner"), "fixture"))
      .rejects.toBeInstanceOf(AuthorizationChangedError);
    expect(await prisma.user.count({ where: { email: email("denied-owner") } })).toBe(0);
    expect(await prisma.auditEvent.count({ where: { actorId: admin.id } })).toBe(0);
  });

  it("blocks cross-origin, missing-origin and non-JSON writes", async () => {
    const { agent } = await login("admin");
    await agent.post("/api/logout").set("Origin", "https://evil.example").send({}).expect(403);
    await agent.post("/api/logout").send({}).expect(403);
    await agent.post("/api/logout").set("Origin", origin).type("form").send({}).expect(403);
    await agent.get("/api/me").expect(200);
  }, 30000);

  it("upgrades legacy password hashes after a successful login", async () => {
    await login("legacy");
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("legacy") } });
    expect(user.passwordHash).toMatch(/^scrypt-v2:/);
    expect(await verifyPassword(password, user.passwordHash)).toBe(true);
    expect(await verifyPassword("wrong", user.passwordHash)).toBe(false);
  }, 30000);

  it("persists password changes and revokes sessions stored in PostgreSQL", async () => {
    const first = await login("legacy");
    const second = await login("legacy");
    const newPassword = "another-integration-test-password";
    await first.agent.post("/api/password").set("Origin", origin)
      .send({ currentPassword: password, newPassword }).expect(200);
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("legacy") } });
    expect(await prisma.auditEvent.findFirst({
      where: { actorId: user.id, action: "PASSWORD_CHANGED" }
    })).toMatchObject({ targetId: user.id, businessId: null });
    await request(app).get("/api/me").set("Cookie", first.cookie).expect(401);
    await second.agent.get("/api/me").expect(401);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: email("legacy"), password }).expect(401);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: email("legacy"), password: newPassword }).expect(200);
  }, 30000);

  it("queues indistinguishable reset requests and consumes a reset exactly once", async () => {
    const user = await prisma.user.create({
      data: { email: email("recovery"), passwordHash: await hashPassword(password) }
    });
    const first = await login("recovery");
    const second = await login("recovery");
    const send = vi.fn().mockResolvedValue(undefined);
    const recovery = new PasswordRecovery(prisma, loginRateLimitStore, "ab".repeat(32), origin, send);
    const recoveryApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, passwordRecovery: recovery
    });
    await request(recoveryApp).post("/api/password-reset/request").set("Origin", "https://evil.example")
      .send({ email: user.email, language: "en" }).expect(403);
    const known = await request(recoveryApp).post("/api/password-reset/request").set("Origin", origin)
      .send({ email: user.email, language: "en" }).expect(202);
    const unknown = await request(recoveryApp).post("/api/password-reset/request").set("Origin", origin)
      .send({ email: email("unknown"), language: "en" }).expect(202);
    expect(known.body).toEqual(unknown.body);
    const queued = await prisma.passwordResetDelivery.findMany();
    recoveryDeliveryIds.push(...queued.map((row) => row.id));
    expect(queued).toHaveLength(2);
    for (const delivery of queued) expect(delivery.payload).not.toContain(user.email);
    await recovery.processOne();
    await recovery.processOne();
    expect(send).toHaveBeenCalledTimes(1);
    const mail = send.mock.calls[0][0];
    expect(mail.to).toBe(user.email);
    const token = new URLSearchParams(new URL(mail.link).hash.slice(1)).get("reset");
    expect(token).toMatch(/^[a-f0-9]{64}$/);
    const newPassword = "recovered-integration-password";
    const attempts = await Promise.all([
      request(recoveryApp).post("/api/password-reset/confirm").set("Origin", origin).send({ token, newPassword }),
      request(recoveryApp).post("/api/password-reset/confirm").set("Origin", origin).send({ token, newPassword })
    ]);
    expect(attempts.map((response) => response.status).sort()).toEqual([200, 400]);
    await request(app).get("/api/me").set("Cookie", first.cookie).expect(401);
    await second.agent.get("/api/me").expect(401);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: user.email, password }).expect(401);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: user.email, password: newPassword }).expect(200);
    expect(await prisma.auditEvent.count({ where: { actorId: user.id, action: "PASSWORD_RESET" } })).toBe(1);
  }, 30000);

  it("retries failed mail delivery and rejects expired reset tokens", async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { email: email("recovery") } });
    const send = vi.fn().mockRejectedValueOnce(new Error("SMTP unavailable")).mockResolvedValue(undefined);
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    const recovery = new PasswordRecovery(prisma, loginRateLimitStore, "ab".repeat(32), origin, send);
    try {
      await recovery.request(user.email, "es");
      const delivery = await prisma.passwordResetDelivery.findFirstOrThrow();
      recoveryDeliveryIds.push(delivery.id);
      await recovery.processOne();
      expect(await prisma.passwordResetDelivery.findUnique({ where: { id: delivery.id } })).not.toBeNull();
      await prisma.passwordResetDelivery.update({
        where: { id: delivery.id }, data: { nextAttemptAt: new Date(Date.now() - 1000) }
      });
      await recovery.processOne();
      expect(send).toHaveBeenCalledTimes(2);
      expect(send.mock.calls[1][0].language).toBe("es");
      const token = new URLSearchParams(new URL(send.mock.calls[1][0].link).hash.slice(1)).get("reset");
      if (!token) throw new Error("Missing test reset token");
      await prisma.passwordResetToken.update({
        where: { id: delivery.id }, data: { expiresAt: new Date(Date.now() - 1000) }
      });
      expect(await recovery.redeem(token, "another-recovered-password")).toBe(false);
    } finally {
      logs.mockRestore();
    }
  }, 30000);

  it("invalidates recovery tokens after a password change and limits requests per address", async () => {
    const user = await prisma.user.create({
      data: { email: email("recovery-stale"), passwordHash: await hashPassword(password) }
    });
    const send = vi.fn().mockResolvedValue(undefined);
    const recovery = new PasswordRecovery(prisma, loginRateLimitStore, "ab".repeat(32), origin, send);
    for (let attempt = 0; attempt < 4; attempt++) await recovery.request(user.email, "en");
    const queued = await prisma.passwordResetDelivery.findMany();
    recoveryDeliveryIds.push(...queued.map((row) => row.id));
    expect(queued).toHaveLength(3);
    await recovery.processOne();
    const token = new URLSearchParams(new URL(send.mock.calls[0][0].link).hash.slice(1)).get("reset");
    if (!token) throw new Error("Missing test reset token");
    expect(await repository.changePassword(user.id, user.passwordHash, await hashPassword("changed-before-reset"))).toBe(true);
    expect(await recovery.redeem(token, "recovered-after-change")).toBe(false);
    await recovery.processOne();
    await recovery.processOne();
    expect(send).toHaveBeenCalledTimes(1);
    await prisma.passwordResetDelivery.deleteMany({ where: { id: { in: queued.map((row) => row.id) } } });
  }, 30000);

  it("does not deliver an earlier request for an account created later", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const recovery = new PasswordRecovery(prisma, loginRateLimitStore, "ab".repeat(32), origin, send);
    await recovery.request(email("recovery-later"), "en");
    const delivery = await prisma.passwordResetDelivery.findFirstOrThrow();
    recoveryDeliveryIds.push(delivery.id);
    await prisma.user.create({
      data: { email: email("recovery-later"), passwordHash: await hashPassword(password) }
    });
    await recovery.processOne();
    expect(send).not.toHaveBeenCalled();
  }, 30000);

  it("does not revive a used token when an ambiguous SMTP delivery is retried", async () => {
    const user = await prisma.user.create({
      data: { email: email("recovery-ambiguous"), passwordHash: await hashPassword(password) }
    });
    let token = "";
    let recovery: PasswordRecovery;
    const send = vi.fn().mockImplementation(async (mail: { link: string }) => {
      token = new URLSearchParams(new URL(mail.link).hash.slice(1)).get("reset") ?? "";
      expect(await recovery.redeem(token, "ambiguous-reset-password")).toBe(true);
      throw new Error("SMTP outcome unknown");
    });
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      recovery = new PasswordRecovery(prisma, loginRateLimitStore, "ab".repeat(32), origin, send);
      await recovery.request(user.email, "en");
      const delivery = await prisma.passwordResetDelivery.findFirstOrThrow();
      recoveryDeliveryIds.push(delivery.id);
      await recovery.processOne();
      await prisma.passwordResetDelivery.update({
        where: { id: delivery.id }, data: { nextAttemptAt: new Date(Date.now() - 1000) }
      });
      await recovery.processOne();
      expect(send).toHaveBeenCalledTimes(1);
      expect(await recovery.redeem(token, "another-reset-password")).toBe(false);
    } finally {
      logs.mockRestore();
    }
  }, 30000);

  it("sets Secure cookies behind the production HTTPS proxy", async () => {
    const productionApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin: "https://pay.example.com", production: true, loginRateLimitStore
    });
    const response = await request(productionApp).post("/api/login").set("Origin", "https://pay.example.com")
      .set("X-Forwarded-Proto", "https").send({ email: email("a"), password }).expect(200);
    expect(firstCookie(response.headers)).toContain("Secure");
  }, 30000);

  it("throttles repeated bad logins before querying a valid account again", async () => {
    const firstApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, loginRateLimitStore
    });
    const secondApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, loginRateLimitStore
    });
    for (let attempt = 0; attempt < 10; attempt++) {
      const instance = attempt % 2 === 0 ? firstApp : secondApp;
      await request(instance).post("/api/login").set("Origin", origin).send({ email: email("a"), password: "wrong" }).expect(401);
    }
    await request(secondApp).post("/api/login").set("Origin", origin).send({ email: email("a"), password }).expect(429);
  }, 30000);

  it("fails closed without checking credentials when the shared limiter is unavailable", async () => {
    const isolatedApp = createApp({
      repository, store, secret: "integration-test-secret-at-least-32-characters",
      origin, production: false, loginRateLimitStore
    });
    const increment = vi.spyOn(loginRateLimitStore, "increment").mockRejectedValueOnce(new Error("database unavailable"));
    const lookup = vi.spyOn(repository, "findUserByEmail");
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await request(isolatedApp).post("/api/login").set("Origin", origin)
        .send({ email: email("a"), password }).expect(500);
      expect(lookup).not.toHaveBeenCalled();
    } finally {
      increment.mockRestore();
      lookup.mockRestore();
      logs.mockRestore();
    }
  });

  it("counts concurrent requests atomically across stores and starts a fresh window after expiry", async () => {
    const otherStore = new PostgresRateLimitStore(prisma);
    const key = `integration-${randomUUID()}`;
    try {
      const results = await Promise.all(Array.from({ length: 30 }, (_, index) =>
        (index % 2 === 0 ? loginRateLimitStore : otherStore).increment(key)));
      expect(results.map((result) => result.totalHits).sort((a, b) => a - b))
        .toEqual(Array.from({ length: 30 }, (_, index) => index + 1));
      expect((await otherStore.get(key))?.totalHits).toBe(30);
      await prisma.loginRateLimit.update({
        where: { key }, data: { resetTime: new Date(Date.now() - 60_000) }
      });
      expect(await loginRateLimitStore.get(key)).toBeUndefined();
      expect((await otherStore.increment(key)).totalHits).toBe(1);
    } finally {
      await loginRateLimitStore.resetKey(key);
    }
  }, 30000);
});
