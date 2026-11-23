import { z } from "zod";
import { loadConfig } from "../config.js";
import { createDatabase } from "../db.js";
import { GoogleSecretManager } from "../secrets/google-secret-manager.js";
import { OAuthRotationError, OAuthTokenRotation } from "./oauth-token-rotation.js";

async function main() {
  const business = z.uuid().safeParse(process.argv[2]);
  if (!business.success || process.argv.length !== 3) {
    console.error("Usage: npm run stripe:oauth-live-refresh -- <business UUID>");
    process.exitCode = 1;
    return;
  }

  const config = loadConfig();
  const projectId = config.STRIPE_OAUTH_LIVE_GCP_PROJECT_ID;
  const secretId = config.STRIPE_OAUTH_LIVE_KEY_SECRET_ID;
  const version = config.STRIPE_OAUTH_LIVE_KEY_SECRET_VERSION;
  if (config.APP_ENV !== "production" || !config.STRIPE_OAUTH_LIVE_CLIENT_ID || !projectId || !secretId || !version ||
      (config.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID && config.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID !== business.data)) {
    console.error("Live OAuth refresh is unavailable for the specified business");
    process.exitCode = 1;
    return;
  }

  const db = createDatabase(config.DATABASE_URL);
  const secrets = new GoogleSecretManager(projectId);
  try {
    const rotation = new OAuthTokenRotation(db.oauthRotation, secrets, () => secrets.accessVersion({ secretId, version }));
    await rotation.rotate(business.data, "LIVE");
    console.log("Live Stripe OAuth credential refreshed");
  } finally {
    db.loginRateLimitStore.shutdown();
    const closed = await Promise.allSettled([secrets.close(), db.prisma.$disconnect()]);
    if (closed.some((result) => result.status === "rejected")) {
      console.error("Live OAuth refresh resources failed to close");
      process.exitCode = 1;
    }
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof OAuthRotationError ? error.message : "Live OAuth refresh failed");
  process.exitCode = 1;
});
