import "dotenv/config";
import Stripe from "stripe";
import { z } from "zod";
import { createDatabase } from "../db.js";
import { GoogleSecretManager } from "../secrets/google-secret-manager.js";
import { verifyRestrictedConnection } from "./checkout-recovery-runtime.js";
import { ProductPublisher, PublicationError } from "./publish-product.js";

const setupSchema = z.object({
  APP_ENV: z.literal("staging"),
  DATABASE_URL: z.url(),
  CHECKOUT_SETUP_ADMIN_EMAIL: z.email(),
  CHECKOUT_SETUP_BUSINESS_ID: z.uuid(),
  CHECKOUT_SETUP_DRAFT_ID: z.uuid(),
  CHECKOUT_SETUP_ACCOUNT_ID: z.string().regex(/^acct_[A-Za-z0-9]+$/),
  CHECKOUT_SETUP_PROJECT_ID: z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/),
  CHECKOUT_SETUP_SECRET_ID: z.string().regex(/^kp-stripe-test-[0-9a-f]{32}$/),
  CHECKOUT_SETUP_SECRET_VERSION: z.string().regex(/^[1-9][0-9]*$/),
  CHECKOUT_SETUP_PUBLISHABLE_KEY: z.string().regex(/^pk_test_[A-Za-z0-9]{10,}$/)
});

class SetupError extends Error {}

async function main() {
  const result = setupSchema.safeParse(process.env);
  if (!result.success) throw new SetupError("Supply the staging checkout setup variables in the pilot guide.");
  const {
    DATABASE_URL, CHECKOUT_SETUP_ADMIN_EMAIL: email, CHECKOUT_SETUP_BUSINESS_ID: businessId,
    CHECKOUT_SETUP_DRAFT_ID: draftId, CHECKOUT_SETUP_ACCOUNT_ID: accountId,
    CHECKOUT_SETUP_PROJECT_ID: projectId, CHECKOUT_SETUP_SECRET_ID: secretId,
    CHECKOUT_SETUP_SECRET_VERSION: version, CHECKOUT_SETUP_PUBLISHABLE_KEY: publishableKey
  } = result.data;
  const db = createDatabase(DATABASE_URL);
  const secrets = new GoogleSecretManager(projectId);
  try {
    const admin = await db.repository.findUserByEmail(email.trim().toLowerCase());
    if (!admin || admin.role !== "ADMIN") throw new SetupError("The configured operator must be a Kuzushi Pay administrator.");
    const storefront = await db.storefrontProposal.find(admin, businessId);
    if (!storefront?.testApprovedAt) throw new SetupError("Approve the storefront for test checkout before running setup.");
    const draft = await db.prisma.productDraft.findFirst({
      where: { id: draftId, businessId, billing: "ONE_TIME", currency: "USD" }, select: { id: true }
    });
    if (!draft) throw new SetupError("Create a one-time USD dummy draft for this business before running setup.");
    const client = await verifyRestrictedConnection(secrets, { secretId, version }, "TEST", accountId, (key) =>
      new Stripe(key, { apiVersion: "2026-10-28.endive", timeout: 10_000, maxNetworkRetries: 0 })
    ).catch(() => {
      throw new SetupError("Could not verify the pinned Stripe test key, account ID, and test mode.");
    });
    const connectionId = await db.bindPilotTestConnection(admin, { businessId, accountId, secretId, version });
    if (!connectionId) throw new SetupError("The business has a different test connection or its authorization changed.");
    const publisher = new ProductPublisher(db.publication, client);
    let existing = await db.prisma.stripePublication.findUnique({
      where: { draftId_mode: { draftId, mode: "TEST" } }
    });
    if (!existing) {
      await publisher.begin(admin, businessId, draftId, "TEST");
      existing = await db.prisma.stripePublication.findUnique({ where: { draftId_mode: { draftId, mode: "TEST" } } });
    }
    if (!existing || existing.businessId !== businessId || existing.connectionId !== connectionId ||
        existing.stripeAccountId !== accountId || existing.billing !== "ONE_TIME") {
      throw new SetupError("The stored publication does not match the approved Stripe test connection.");
    }
    await publisher.resume(admin, businessId, existing.id);
    const current = await db.storefrontProposal.find(admin, businessId);
    if (current?.revision !== storefront.revision || !current.testApprovedAt) {
      throw new SetupError("The storefront changed during setup. Approve the current revision and rerun setup.");
    }
    console.log(JSON.stringify({
      businessId, connectionId, publicationId: existing.id, revision: current.revision,
      origin: current.origin, accountId, projectId, publishableKey
    }));
  } finally {
    const closed = await Promise.allSettled([secrets.close(), db.prisma.$disconnect()]);
    if (closed.some((result) => result.status === "rejected")) console.error("Checkout setup resource cleanup failed.");
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof SetupError ? error.message
    : error instanceof PublicationError ? `Stripe test publication failed (${error.code}).`
    : "Checkout pilot setup failed. Check the staging database and credential configuration.");
  process.exitCode = 1;
});
