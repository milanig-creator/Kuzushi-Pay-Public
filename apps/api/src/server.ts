import { resolve } from "node:path";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { Pool } from "pg";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createDatabase } from "./db.js";
import { SandboxOAuthService } from "./stripe/oauth-sandbox.js";
import { SandboxIdentityExchange, sandboxDeveloperCredential, encodeStripeOAuthTokens } from "./stripe/oauth-sandbox-exchange.js";
import { currentUser } from "./authentication.js";
import { GoogleSecretManager } from "./secrets/google-secret-manager.js";
import nodemailer from "nodemailer";
import { PasswordRecovery } from "./password-recovery.js";
import { recoveryMessage } from "./recovery-mail.js";
import { MfaStore } from "./mfa-store.js";
import { PostgresRateLimitStore } from "./postgres-rate-limit-store.js";
import { CheckoutRecoveryRuntime } from "./stripe/checkout-recovery-runtime.js";
import { CheckoutRecoveryWorker } from "./stripe/checkout-recovery-worker.js";
import { CheckoutService, CheckoutServiceError } from "./stripe/checkout-service.js";
import { ProductPublisher, PublicationError } from "./stripe/publish-product.js";
import { loadLiveOAuthClient } from "./stripe/live-oauth-client.js";
import { OAuthTokenRotation } from "./stripe/oauth-token-rotation.js";
import { CheckoutWebhookReceiver } from "./stripe/checkout-webhook.js";
import { CheckoutEventRunner, CheckoutEventWorker } from "./stripe/checkout-event-worker.js";
import Stripe from "stripe";
import { ConnectOnboarding, ConnectOnboardingStore } from "./stripe/connect-onboarding.js";
import { LiveStripeOAuth } from "./stripe/oauth-live.js";
import { createHash } from "node:crypto";

const config = loadConfig();
const {
  prisma, repository, oauthAttempts, loginRateLimitStore, storefrontProposal, checkout,
  checkoutRecoveryBindings, checkoutRecoveryWork, checkoutReconciliation, checkoutEventWork, checkoutWebhook, publication,
  sandboxOAuthBinding, liveOAuthState, bindLiveOAuth, oauthRotation, findLiveOAuthCredential
} = createDatabase(config.DATABASE_URL);
const liveOAuthSecrets = config.STRIPE_OAUTH_LIVE_GCP_PROJECT_ID
  ? new GoogleSecretManager(config.STRIPE_OAUTH_LIVE_GCP_PROJECT_ID) : undefined;
const liveKeyId = config.STRIPE_OAUTH_LIVE_KEY_SECRET_ID;
const liveKeyVersion = config.STRIPE_OAUTH_LIVE_KEY_SECRET_VERSION;
const liveOAuth = liveOAuthSecrets && config.STRIPE_OAUTH_LIVE_CLIENT_ID && liveKeyId && liveKeyVersion
  ? new LiveStripeOAuth(repository, {
    ...liveOAuthState,
    async bind(actor, businessId, tokens) {
      const secretId = `kp-stripe-oauth-live-${createHash("sha256").update(businessId).digest("hex").slice(0, 32)}`;
      await liveOAuthSecrets.ensureLiveOAuthSecret(secretId);
      const reference = await liveOAuthSecrets.addVersion(secretId, encodeStripeOAuthTokens(tokens, Date.now()));
      const bound = await bindLiveOAuth(actor, businessId, tokens.accountId, reference);
      if (!bound) await liveOAuthSecrets.disableVersion(reference);
      return bound;
    }
  }, config.APP_ORIGIN, config.STRIPE_OAUTH_LIVE_CLIENT_ID, config.SESSION_SECRET,
  () => liveOAuthSecrets.accessVersion({ secretId: liveKeyId, version: liveKeyVersion }), undefined,
  config.STRIPE_OAUTH_LIVE_TEST_CHANNEL && config.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID ? {
    channel: config.STRIPE_OAUTH_LIVE_TEST_CHANNEL, businessId: config.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID
  } : undefined, config.STRIPE_OAUTH_LIVE_PUBLIC_CLIENT_ID) : undefined;
const storefrontRateLimitStore = new PostgresRateLimitStore(prisma);
const connectMode = config.APP_ENV === "production" ? "LIVE" : "TEST";
const connectRateLimitStore = config.STRIPE_CONNECT_PLATFORM_KEY || liveOAuth ? new PostgresRateLimitStore(prisma) : undefined;
const connectOnboarding = config.STRIPE_CONNECT_PLATFORM_KEY ? new ConnectOnboardingStore(prisma,
  new ConnectOnboarding(new Stripe(config.STRIPE_CONNECT_PLATFORM_KEY, { timeout: 5000, maxNetworkRetries: 1 }).v2.core,
    config.APP_ORIGIN, connectMode === "LIVE"), connectMode) : undefined;
const mfa = config.MFA_ENABLED === "true" && config.MFA_KEY
  ? new MfaStore(prisma, config.MFA_KEY, loginRateLimitStore) : undefined;
if (mfa) await mfa.initialize();
if (!mfa && (await prisma.mfaAuthenticator.count() > 0 || await prisma.mfaRecoveryGrant.count() > 0)) {
  throw new Error("Cannot disable MFA while enrolled accounts exist");
}
const sandboxOAuth = config.STRIPE_OAUTH_SANDBOX_ENABLED === "true" &&
  config.STRIPE_OAUTH_SANDBOX_INSTALL_URL && config.STRIPE_OAUTH_SANDBOX_REDIRECT_URI
  ? new SandboxOAuthService(repository, oauthAttempts, {
    installUrl: config.STRIPE_OAUTH_SANDBOX_INSTALL_URL,
    redirectUri: config.STRIPE_OAUTH_SANDBOX_REDIRECT_URI,
    businessId: config.STRIPE_OAUTH_SANDBOX_BUSINESS_ID
  }, config.SESSION_SECRET) : undefined;
if (sandboxOAuth && config.STRIPE_OAUTH_SANDBOX_REDIRECT_URI &&
    new URL(config.STRIPE_OAUTH_SANDBOX_REDIRECT_URI).origin !== config.APP_ORIGIN) {
  throw new Error("Sandbox OAuth callback must use APP_ORIGIN");
}
const sandboxSecrets = config.STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED === "true" && config.STRIPE_OAUTH_SANDBOX_GCP_PROJECT_ID
  ? new GoogleSecretManager(config.STRIPE_OAUTH_SANDBOX_GCP_PROJECT_ID) : undefined;
const sandboxBusinessId = config.STRIPE_OAUTH_SANDBOX_BUSINESS_ID;
const sandboxTokenSecretId = config.STRIPE_OAUTH_SANDBOX_TOKEN_SECRET_ID;
const sandboxExchange = sandboxOAuth && sandboxSecrets &&
  config.STRIPE_OAUTH_SANDBOX_SECRET_ID && config.STRIPE_OAUTH_SANDBOX_SECRET_VERSION &&
  config.STRIPE_OAUTH_SANDBOX_EXPECTED_ACCOUNT_ID
  ? new SandboxIdentityExchange("staging", sandboxOAuth,
    sandboxDeveloperCredential(sandboxSecrets, {
      secretId: config.STRIPE_OAUTH_SANDBOX_SECRET_ID, version: config.STRIPE_OAUTH_SANDBOX_SECRET_VERSION
    }), config.STRIPE_OAUTH_SANDBOX_EXPECTED_ACCOUNT_ID, undefined,
    sandboxBusinessId && sandboxTokenSecretId ? async (session, tokens) => {
      const actor = await currentUser(repository, session);
      if (!actor) return false;
      const connectionId = await sandboxOAuthBinding.reserve(actor, sandboxBusinessId, tokens.accountId);
      if (!connectionId) return false;
      const reference = await sandboxSecrets.addVersion(sandboxTokenSecretId, encodeStripeOAuthTokens(tokens));
      if (reference.secretId !== sandboxTokenSecretId || !/^[1-9][0-9]*$/.test(reference.version)) return false;
      const current = await currentUser(repository, session);
      return !!current && await sandboxOAuthBinding.complete(current, sandboxBusinessId, connectionId, tokens.accountId, reference);
    } : undefined)
  : undefined;
const pool = new Pool({ connectionString: config.DATABASE_URL });
pool.on("error", () => console.error("Session database error"));
const PgStore = connectPgSimple(session);
const smtpFrom = config.SMTP_FROM;
const mailTransport = config.PASSWORD_RESET_ENABLED === "true" &&
  config.SMTP_HOST && config.SMTP_PORT && config.SMTP_SECURE && smtpFrom
  ? nodemailer.createTransport({
    host: config.SMTP_HOST, port: config.SMTP_PORT, secure: config.SMTP_SECURE === "true",
    requireTLS: true, connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000,
    auth: config.SMTP_USER && config.SMTP_PASSWORD
      ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined
  }) : undefined;
const passwordRecovery = config.PASSWORD_RESET_ENABLED === "true" && config.PASSWORD_RESET_KEY &&
  smtpFrom && mailTransport
  ? new PasswordRecovery(prisma, loginRateLimitStore, config.PASSWORD_RESET_KEY, config.APP_ORIGIN, async (mail) => {
    const result = await mailTransport.sendMail(recoveryMessage(smtpFrom, mail));
    if (result.accepted.length !== 1 || result.rejected.length) throw new Error("SMTP delivery was not accepted");
  }) : undefined;
const pilot = config.CHECKOUT_PILOT_CONFIG;
const liveCheckout = config.CHECKOUT_LIVE_CONFIG;
const liveCheckoutRateLimitStore = liveCheckout && new PostgresRateLimitStore(prisma);
const liveOAuthRotation = liveOAuth && liveOAuthSecrets && liveKeyId && liveKeyVersion
  ? new OAuthTokenRotation(oauthRotation, liveOAuthSecrets,
    () => liveOAuthSecrets.accessVersion({ secretId: liveKeyId, version: liveKeyVersion }))
  : undefined;
const loadLiveCheckoutBinding = liveCheckout && liveOAuthSecrets && liveOAuthRotation &&
  (() => loadLiveOAuthClient(
      liveCheckout.businessId, liveCheckout.accountId, async (businessId) => {
        const current = await findLiveOAuthCredential(businessId);
        return current?.connectionId === liveCheckout.connectionId ? current : null;
      }, liveOAuthSecrets, liveOAuthRotation
  ));
const liveCheckoutRunner = liveOAuthSecrets && liveOAuthRotation && new CheckoutEventRunner({
  async processOne() {
    const now = new Date();
    const work = await prisma.checkoutRecoveryWork.findFirst({
      where: {
        OR: [{ status: "PENDING", nextAttemptAt: { lte: now } }, { status: "PROCESSING", leaseUntil: { lte: now } }],
        attempt: { status: "SESSION_CREATED", order: { publication: {
          mode: "LIVE", connection: { status: "VERIFIED", oauthCredential: { is: { status: "READY" } } }
        } } }
      },
      orderBy: [{ nextAttemptAt: "asc" }, { attemptId: "asc" }],
      select: { attempt: { select: { order: { select: { publication: {
        select: { businessId: true, connectionId: true }
      } } } } } }
    });
    if (!work) return { state: "idle" };
    const { businessId, connectionId } = work.attempt.order.publication;
    return new CheckoutRecoveryWorker(checkoutRecoveryWork, checkoutReconciliation, {
      async loadLiveClient(accountId) {
        const binding = await loadLiveOAuthClient(businessId, accountId, async (id) => {
          const current = await findLiveOAuthCredential(id);
          return current?.connectionId === connectionId ? current : null;
        }, liveOAuthSecrets, liveOAuthRotation);
        return binding.client;
      }
    }, businessId, connectionId).processOne();
  }
},
  (notice) => console.error("Live checkout recovery notice", notice)
);
const pilotWebhookSecret = config.CHECKOUT_PILOT_WEBHOOK_SECRET;
const pilotSecrets = pilot && new GoogleSecretManager(pilot.projectId);
const pilotRateLimitStore = pilot && new PostgresRateLimitStore(prisma);
const pilotRuntime = pilot && pilotSecrets && new CheckoutRecoveryRuntime(
  checkoutRecoveryBindings, pilotSecrets, checkoutRecoveryWork, checkoutReconciliation,
  pilot.businessId, pilot.connectionId, "TEST"
);
const pilotWebhook = pilot && pilotWebhookSecret ? new CheckoutWebhookReceiver({
  resolve: async (connectionId) => {
    if (connectionId !== pilot.connectionId) return null;
    const current = await checkoutRecoveryBindings.find(pilot.businessId, connectionId, "TEST");
    return current?.accountId === pilot.accountId ? {
      binding: { businessId: pilot.businessId, connectionId, accountId: current.accountId, mode: "TEST", source: "direct" },
      secrets: [pilotWebhookSecret]
    } : null;
  }
}, checkoutWebhook) : undefined;
const pilotRunner = pilot && pilotRuntime && new CheckoutEventRunner({
  processOne: async () => {
    const client = await pilotRuntime.prepare(pilot.accountId);
    return new CheckoutEventWorker(
      checkoutEventWork, checkoutReconciliation, client, pilot.businessId, pilot.connectionId
    ).processOne();
  }
}, (notice) => console.error("Checkout pilot event worker", notice));
const app = createApp({
  liveOAuth,
  ownerCheckout: liveOAuth && liveOAuthSecrets && liveOAuthRotation && {
    async list(businessId) {
      const orders = await prisma.checkoutOrder.findMany({
        where: { publication: { businessId, mode: "LIVE" }, attempt: { status: "SESSION_CREATED" } },
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: 20,
        select: { id: true, createdAt: true, initialPaymentStatus: true, paidQuantity: true,
          publication: { select: { name: true } } }
      });
      return orders.map((order) => ({
        id: order.id, name: order.publication.name, createdAt: order.createdAt,
        status: order.initialPaymentStatus, quantity: order.paidQuantity
      }));
    },
    async create(actor, businessId, draftId, requestId) {
      if (await liveOAuth.status(actor, businessId) !== "connected") throw new CheckoutServiceError("UNAVAILABLE");
      const published = await prisma.stripePublication.findFirst({
        where: { businessId, draftId, mode: "LIVE", status: "PRICE_CREATED" },
        select: { id: true, connectionId: true, stripeAccountId: true }
      });
      if (!published) throw new CheckoutServiceError("UNAVAILABLE");
      const binding = await loadLiveOAuthClient(businessId, published.stripeAccountId, async (id) => {
        const current = await findLiveOAuthCredential(id);
        return current?.connectionId === published.connectionId ? current : null;
      }, liveOAuthSecrets, liveOAuthRotation).catch(() => { throw new CheckoutServiceError("PREPARATION_FAILED"); });
      const demoKey = liveCheckout?.businessId === businessId && liveCheckout.connectionId === binding.connectionId &&
        liveCheckout.accountId === binding.accountId ? liveCheckout.publishableKey : undefined;
      const publishableKey = binding.publishableKey ?? demoKey;
      if (!publishableKey) throw new CheckoutServiceError("UNAVAILABLE");
      const service = new CheckoutService(checkout, binding.client, businessId, {
        origin: config.APP_ORIGIN, revision: null, mode: "LIVE", connectionId: binding.connectionId, requestId,
        dashboardReturnUrl: `${config.APP_ORIGIN}/?session_id={CHECKOUT_SESSION_ID}`
      }, undefined, binding);
      const { attemptId } = await service.begin(published.id);
      return { ...await service.create(attemptId), publishableKey };
    }
  },
  livePublication: liveOAuth && liveOAuthSecrets && liveOAuthRotation && {
    async list(businessId) {
      const rows = await prisma.stripePublication.findMany({
        where: { businessId, mode: "LIVE" }, select: { draftId: true, status: true }
      });
      return rows.map(({ draftId, status }) => ({ draftId, published: status === "PRICE_CREATED" }));
    },
    async publish(actor, businessId, draftId) {
      if (await liveOAuth.status(actor, businessId) !== "connected" ||
          !await prisma.productDraft.findFirst({ where: { id: draftId, businessId }, select: { id: true } })) {
        throw new PublicationError("UNAVAILABLE");
      }
      const credential = await findLiveOAuthCredential(businessId);
      if (!credential) throw new PublicationError("UNAVAILABLE");
      const binding = await loadLiveOAuthClient(
        businessId, credential.accountId, findLiveOAuthCredential, liveOAuthSecrets, liveOAuthRotation
      ).catch(() => { throw new PublicationError("PREPARATION_FAILED"); });
      const publisher = new ProductPublisher(publication, binding.client, binding);
      const existing = await prisma.stripePublication.findUnique({
        where: { draftId_mode: { draftId, mode: "LIVE" } },
        select: { id: true, businessId: true, connectionId: true, stripeAccountId: true, status: true }
      });
      if (existing && (existing.businessId !== businessId || existing.connectionId !== binding.connectionId ||
          existing.stripeAccountId !== binding.accountId)) throw new PublicationError("UNAVAILABLE");
      if (existing?.status === "PRICE_CREATED") return;
      const publicationId = existing?.id ?? (await publisher.begin(actor, businessId, draftId, "LIVE")).publicationId;
      await publisher.resume(actor, businessId, publicationId);
    }
  },
  connectOnboarding,
  connectRateLimitStore,
  repository,
  store: new PgStore({
    pool,
    tableName: "session",
    errorLog: () => console.error("Session store maintenance failed")
  }),
  secret: config.SESSION_SECRET,
  origin: config.APP_ORIGIN,
  production: config.NODE_ENV === "production",
  loginRateLimitStore,
  storefront: { proposals: storefrontProposal, rateLimitStore: storefrontRateLimitStore },
  passwordRecovery,
  mfa,
  sandboxOAuth,
  sandboxExchange,
  sandboxOAuthStatus: sandboxExchange && sandboxTokenSecretId ? sandboxOAuthBinding.status : undefined,
  checkoutWebhook: pilotWebhook,
  liveCheckout: liveCheckout && liveCheckoutRateLimitStore && loadLiveCheckoutBinding && {
    origin: liveCheckout.origin,
    previewToken: config.CHECKOUT_LIVE_PREVIEW_TOKEN,
    publishableKey: liveCheckout.publishableKey,
    rateLimitStore: liveCheckoutRateLimitStore,
    async create(requestId) {
      const binding = await loadLiveCheckoutBinding();
      const service = new CheckoutService(checkout, binding.client, liveCheckout.businessId, {
        origin: liveCheckout.origin, revision: liveCheckout.revision,
        connectionId: binding.connectionId, mode: "LIVE", requestId
      }, undefined, binding);
      const { attemptId } = await service.begin(liveCheckout.publicationId);
      const session = await service.create(attemptId);
      return { ...session, publishableKey: binding.publishableKey };
    }
  },
  checkoutPilot: pilot && pilotRuntime && pilotRateLimitStore && {
    businessId: pilot.businessId,
    origin: pilot.origin,
    publishableKey: pilot.publishableKey,
    rateLimitStore: pilotRateLimitStore,
    listOrders: () => prisma.checkoutOrder.findMany({
      where: {
        publicationId: pilot.publicationId, storefrontRequestId: { not: null },
        publication: { businessId: pilot.businessId, connectionId: pilot.connectionId, mode: "TEST" }
      },
      select: { id: true, createdAt: true, initialPaymentStatus: true },
      orderBy: { createdAt: "desc" }, take: 10
    }),
    create: async (requestId) => {
      const client = await pilotRuntime.prepare(pilot.accountId);
      const service = new CheckoutService(checkout, client, pilot.businessId, {
        origin: pilot.origin, revision: pilot.revision, connectionId: pilot.connectionId, requestId
      });
      const { attemptId } = await service.begin(pilot.publicationId);
      return service.create(attemptId);
    }
  },
  staging: config.APP_ENV === "staging"
});
passwordRecovery?.start();
pilotRunner?.start();
if (liveCheckoutRunner) {
  liveCheckoutRunner.start();
  console.log("Live checkout recovery worker started");
}
if (config.NODE_ENV === "production") {
  if (pilot) app.get("/checkout-pilot.js", (_req, res) => {
    res.set("Cross-Origin-Resource-Policy", "cross-origin");
    res.sendFile(resolve("apps/web/dist/checkout-pilot.js"));
  });
  app.use(express.static(resolve("apps/web/dist")));
  app.get("/", (_req, res) => res.sendFile(resolve("apps/web/dist/index.html")));
}
const server = app.listen(config.PORT, () => console.log(`Kuzushi Pay listening on port ${config.PORT}`));
let shutdownStarted = false;

async function shutdown(signal: NodeJS.Signals) {
  if (shutdownStarted) return;
  shutdownStarted = true;
  console.log(`Kuzushi Pay shutting down after ${signal}`);
  const forceClose = setTimeout(() => {
    console.error("Graceful shutdown timed out; closing active connections");
    server.closeAllConnections();
    process.exit(1);
  }, 10_000);
  forceClose.unref();

  await new Promise<void>((resolve) => {
    server.close((error) => {
      if (error) {
        console.error("HTTP server shutdown failed", error);
        process.exitCode = 1;
      }
      resolve();
    });
  });
  await Promise.all([passwordRecovery?.stop(), pilotRunner?.stop(), liveCheckoutRunner && liveCheckoutRunner.stop()]);
  await Promise.allSettled([pilotSecrets?.close(), sandboxSecrets?.close(), liveOAuthSecrets?.close()]);
  mailTransport?.close();
  loginRateLimitStore.shutdown();
  storefrontRateLimitStore.shutdown();
  connectRateLimitStore?.shutdown();
  pilotRateLimitStore?.shutdown();
  liveCheckoutRateLimitStore?.shutdown();
  await Promise.all([
    pool.end().catch((error: unknown) => {
      console.error("Session database shutdown failed", error);
      process.exitCode = 1;
    }),
    prisma.$disconnect().catch((error: unknown) => {
      console.error("Application database shutdown failed", error);
      process.exitCode = 1;
    })
  ]);
  clearTimeout(forceClose);
  console.log("Kuzushi Pay shutdown complete");
}

process.once("SIGTERM", () => { void shutdown("SIGTERM"); });
process.once("SIGINT", () => { void shutdown("SIGINT"); });
