import "dotenv/config";
import { z } from "zod";
import { createDatabase } from "../db.js";
import { GoogleSecretManager } from "../secrets/google-secret-manager.js";
import { CheckoutEventRunner } from "./checkout-event-worker.js";
import { CheckoutRecoveryRuntime } from "./checkout-recovery-runtime.js";
import { CheckoutRecoveryWorker } from "./checkout-recovery-worker.js";
import { loadConfig } from "../config.js";
import { OAuthTokenRotation } from "./oauth-token-rotation.js";
import { loadLiveOAuthClient } from "./live-oauth-client.js";

const invalidConfiguration = () => new Error("Invalid checkout recovery configuration");

function oauthConfiguration(businessId: string) {
  const config = loadConfig();
  const { STRIPE_OAUTH_LIVE_GCP_PROJECT_ID: projectId, STRIPE_OAUTH_LIVE_KEY_SECRET_ID: secretId,
    STRIPE_OAUTH_LIVE_KEY_SECRET_VERSION: version, STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID: testBusinessId } = config;
  if (config.APP_ENV !== "production" || !config.STRIPE_OAUTH_LIVE_CLIENT_ID || !projectId || !secretId || !version ||
      (testBusinessId && testBusinessId !== businessId)) throw invalidConfiguration();
  return { projectId, secretId, version };
}

async function main() {
  const parsed = z.object({
    DATABASE_URL: z.string().url(),
    STRIPE_RECOVERY_SOURCE: z.enum(["direct", "oauth"]).default("direct"),
    STRIPE_RECOVERY_GCP_PROJECT_ID: z.string().min(1).optional(),
    STRIPE_RECOVERY_ACCOUNT_ID: z.string().regex(/^acct_[A-Za-z0-9]+$/).optional(),
    STRIPE_RECOVERY_BUSINESS_ID: z.string().uuid(),
    STRIPE_RECOVERY_CONNECTION_ID: z.string().uuid(),
    STRIPE_RECOVERY_MODE: z.enum(["TEST", "LIVE"])
  }).safeParse(process.env);
  if (!parsed.success) throw invalidConfiguration();
  const config = parsed.data;
  const { STRIPE_RECOVERY_BUSINESS_ID: businessId, STRIPE_RECOVERY_CONNECTION_ID: connectionId,
    STRIPE_RECOVERY_MODE: mode, STRIPE_RECOVERY_ACCOUNT_ID: accountId } = config;
  if (config.STRIPE_RECOVERY_SOURCE === "oauth" && (mode !== "LIVE" || !accountId)) throw invalidConfiguration();
  const oauth = config.STRIPE_RECOVERY_SOURCE === "oauth" ? oauthConfiguration(businessId) : undefined;
  const projectId = oauth?.projectId ?? config.STRIPE_RECOVERY_GCP_PROJECT_ID;
  if (!projectId) throw invalidConfiguration();
  const secrets = new GoogleSecretManager(projectId);
  const db = createDatabase(config.DATABASE_URL);
  let forceClose: NodeJS.Timeout | undefined;
  try {
    let worker: CheckoutRecoveryRuntime | CheckoutRecoveryWorker;
    if (oauth) {
      const findBinding = async (id: string) => {
        const binding = await db.findLiveOAuthCredential(id);
        return binding?.connectionId === connectionId && binding.accountId === accountId ? binding : null;
      };
      if (!await findBinding(businessId)) throw new Error("Checkout recovery connection unavailable");
      const rotation = new OAuthTokenRotation(db.oauthRotation, secrets, () =>
        secrets.accessVersion({ secretId: oauth.secretId, version: oauth.version }));
      worker = new CheckoutRecoveryWorker(db.checkoutRecoveryWork, db.checkoutReconciliation, {
        loadLiveClient: async (expectedAccountId) => {
          if (expectedAccountId !== accountId) throw new Error("Checkout recovery connection unavailable");
          return (await loadLiveOAuthClient(businessId, expectedAccountId, findBinding, secrets, rotation)).client;
        }
      }, businessId, connectionId);
    } else {
      worker = new CheckoutRecoveryRuntime(db.checkoutRecoveryBindings, secrets, db.checkoutRecoveryWork,
        db.checkoutReconciliation, businessId, connectionId, mode);
      await worker.prepare(accountId);
    }
    const runner = new CheckoutEventRunner(worker, (notice) => {
      console.error("Checkout recovery worker notice", notice);
    }, false);
    const signal = new Promise<NodeJS.Signals>((resolve) => {
      process.once("SIGTERM", () => resolve("SIGTERM"));
      process.once("SIGINT", () => resolve("SIGINT"));
    });
    runner.start();
    console.log("Checkout recovery worker started");
    const received = await signal;
    console.log(`Checkout recovery worker stopping after ${received}`);
    forceClose = setTimeout(() => {
      console.error("Checkout recovery shutdown timed out");
      process.exit(1);
    }, 30_000);
    forceClose.unref();
    await runner.stop();
  } finally {
    db.loginRateLimitStore.shutdown();
    const closed = await Promise.allSettled([secrets.close(), db.prisma.$disconnect()]);
    if (forceClose) clearTimeout(forceClose);
    if (closed.some((result) => result.status === "rejected")) throw new Error("Checkout recovery shutdown failed");
  }
}

main().catch((error: unknown) => {
  const known = ["Invalid checkout recovery configuration", "Checkout recovery connection unavailable",
    "Checkout recovery credential verification failed", "Checkout recovery shutdown failed"];
  console.error(error instanceof Error && known.includes(error.message)
    ? error.message : "Checkout recovery worker failed to start or stop");
  process.exitCode = 1;
});
