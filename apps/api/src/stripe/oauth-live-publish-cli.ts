import { z } from "zod";
import { loadConfig } from "../config.js";
import { createDatabase } from "../db.js";
import { GoogleSecretManager } from "../secrets/google-secret-manager.js";
import { loadLiveOAuthClient } from "./live-oauth-client.js";
import { OAuthRotationError, OAuthTokenRotation } from "./oauth-token-rotation.js";
import { ProductPublisher, PublicationError } from "./publish-product.js";

async function main() {
  const input = z.tuple([z.uuid(), z.uuid(), z.string().regex(/^acct_[A-Za-z0-9]+$/)])
    .safeParse(process.argv.slice(2));
  const email = z.email().safeParse(process.env.STRIPE_LIVE_PUBLISH_ADMIN_EMAIL?.trim().toLowerCase());
  if (!input.success || !email.success) {
    console.error("Set STRIPE_LIVE_PUBLISH_ADMIN_EMAIL and run npm run stripe:oauth-live-publish -- <business UUID> <draft UUID> <Stripe account ID>");
    process.exitCode = 1;
    return;
  }
  const [businessId, draftId, accountId] = input.data;
  const config = loadConfig();
  const projectId = config.STRIPE_OAUTH_LIVE_GCP_PROJECT_ID;
  const secretId = config.STRIPE_OAUTH_LIVE_KEY_SECRET_ID;
  const version = config.STRIPE_OAUTH_LIVE_KEY_SECRET_VERSION;
  if (config.APP_ENV !== "production" || !config.STRIPE_OAUTH_LIVE_CLIENT_ID || !projectId || !secretId || !version ||
      (config.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID && config.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID !== businessId)) {
    throw new PublicationError("UNAVAILABLE");
  }

  const db = createDatabase(config.DATABASE_URL);
  const secrets = new GoogleSecretManager(projectId);
  try {
    const actor = await db.repository.findUserByEmail(email.data);
    if (!actor || actor.role !== "ADMIN" ||
        !await db.prisma.productDraft.findFirst({ where: { id: draftId, businessId }, select: { id: true } })) {
      throw new PublicationError("UNAVAILABLE");
    }
    const rotation = new OAuthTokenRotation(db.oauthRotation, secrets, () => secrets.accessVersion({ secretId, version }));
    const binding = await loadLiveOAuthClient(businessId, accountId, db.findLiveOAuthCredential, secrets, rotation);
    const publisher = new ProductPublisher(db.publication, binding.client, binding);
    const existing = await db.prisma.stripePublication.findUnique({ where: { draftId_mode: { draftId, mode: "LIVE" } } });
    if (existing && (existing.businessId !== businessId || existing.connectionId !== binding.connectionId ||
        existing.stripeAccountId !== accountId)) throw new PublicationError("UNAVAILABLE");
    const publicationId = existing?.id ?? (await publisher.begin(actor, businessId, draftId, "LIVE")).publicationId;
    console.log(JSON.stringify({ publicationId, ...await publisher.resume(actor, businessId, publicationId) }));
  } finally {
    db.loginRateLimitStore.shutdown();
    const closed = await Promise.allSettled([secrets.close(), db.prisma.$disconnect()]);
    if (closed.some((result) => result.status === "rejected")) {
      console.error("Live Stripe publication resources failed to close");
      process.exitCode = 1;
    }
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof PublicationError ? `Live Stripe publication failed (${error.code})`
    : error instanceof OAuthRotationError ? error.message : "Live Stripe publication preparation failed");
  process.exitCode = 1;
});
