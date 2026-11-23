import express, { type ErrorRequestHandler, type Request } from "express";
import session from "express-session";
import helmet from "helmet";
import { ipKeyGenerator, rateLimit, type Store } from "express-rate-limit";
import { z } from "zod";
import { hashPassword, passwordNeedsUpgrade, PasswordWorkLimitError, verifyPassword } from "./security.js";
import { AuthorizationChangedError, EmailInUseError, type Repository, type User } from "./repository.js";
import { currentUser, sessionLifetimeMs } from "./authentication.js";
import type { SandboxOAuthService } from "./stripe/oauth-sandbox.js";
import type { SandboxIdentityExchange } from "./stripe/oauth-sandbox-exchange.js";
import type { PasswordRecovery } from "./password-recovery.js";
import { MfaRateLimitError, type MfaStore } from "./mfa-store.js";
import type { SandboxWebhookVerifier } from "./stripe/sandbox-webhook.js";
import type { CheckoutWebhookReceiver } from "./stripe/checkout-webhook.js";
import { checkoutPilotRouter } from "./stripe/checkout-pilot.js";
import { storefrontDnsChallenge, storefrontSetupSchema, type StorefrontProposal, type StorefrontProposalStore } from "./stripe/storefront-proposal.js";
import type { ConnectOnboardingStore } from "./stripe/connect-onboarding.js";
import type { LiveStripeOAuth } from "./stripe/oauth-live.js";
import { PublicationError } from "./stripe/publish-product.js";
import { CheckoutServiceError } from "./stripe/checkout-service.js";

function storefrontResponse(proposal: StorefrontProposal | null) {
  return { proposal: proposal && {
    origin: proposal.origin, returnUrl: proposal.returnUrl, revision: proposal.revision,
    verifiedAt: proposal.verifiedAt, testApprovedAt: proposal.testApprovedAt, challenge: storefrontDnsChallenge(proposal)
  } };
}

declare module "express-session" {
  interface SessionData {
    userId: string;
    authenticatedAt: number;
    authVersion: number;
    mfaVerified?: boolean;
    mfaPending?: {
      userId: string; version: number; startedAt: number; keyFingerprint: string;
      pendingSecret?: string; recoveryRequired?: boolean; recoveryProof?: string;
    };
  }
}

const emailSchema = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const passwordSchema = z.string().min(12).max(128);
const loginSchema = z.object({ email: emailSchema, password: z.string().min(1).max(128) }).strict();
const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: passwordSchema
}).strict();
const businessSchema = z.object({ name: z.string().trim().min(1).max(120), email: emailSchema, password: passwordSchema }).strict();
const productDraftSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(500),
  kind: z.enum(["PHYSICAL", "DIGITAL", "SERVICE"]),
  amountCents: z.number().int().min(1).max(99999999),
  billing: z.enum(["ONE_TIME", "RECURRING"]),
  interval: z.enum(["DAY", "WEEK", "MONTH", "YEAR"]).nullable()
}).strict().refine((draft) => draft.billing === "ONE_TIME" ? draft.interval === null : draft.interval !== null);
const dummyHash = `scrypt-v2:${"00".repeat(16)}:${"00".repeat(64)}`;

export function createApp(options: {
  repository: Repository;
  store: session.Store;
  secret: string;
  origin: string;
  production: boolean;
  loginRateLimitStore?: Store;
  connectOnboarding?: Pick<ConnectOnboardingStore, "status" | "start">;
  connectRateLimitStore?: Store;
  liveOAuth?: Pick<LiveStripeOAuth, "start" | "finish" | "status">;
  livePublication?: {
    list(businessId: string): Promise<{ draftId: string; published: boolean }[]>;
    publish(actor: User, businessId: string, draftId: string): Promise<void>;
  };
  ownerCheckout?: {
    create(actor: User, businessId: string, draftId: string, requestId: string):
      Promise<{ clientSecret: string; publishableKey: string }>;
    list(businessId: string): Promise<{
      id: string; name: string; createdAt: Date; status: "PAID" | "UNPAID"; quantity: number | null;
    }[]>;
  };
  storefront?: { proposals: StorefrontProposalStore; rateLimitStore?: Store };
  passwordRecovery?: Pick<PasswordRecovery, "request" | "redeem">;
  mfa?: Pick<MfaStore, "keyFingerprint" | "isEnrolled" | "requiresRecovery" | "recoveryProofValid" | "prepareEnrollment" |
    "enroll" | "verify" | "replaceBackupCodes" | "verifyRecoveryCode" | "issueRecovery">;
  sandboxOAuth?: SandboxOAuthService;
  sandboxExchange?: SandboxIdentityExchange;
  sandboxOAuthStatus?: (user: User, businessId: string) => Promise<"available" | "connected" | "unavailable">;
  sandboxWebhook?: Pick<SandboxWebhookVerifier, "verify">;
  checkoutWebhook?: Pick<CheckoutWebhookReceiver, "accept">;
  liveCheckout?: Omit<Parameters<typeof checkoutPilotRouter>[0], "mode">;
  checkoutPilot?: Parameters<typeof checkoutPilotRouter>[0] & {
    businessId: string;
    listOrders(): Promise<{ id: string; createdAt: Date; initialPaymentStatus: "PAID" | "UNPAID" }[]>;
  };
  staging?: boolean;
}) {
  if (options.production && options.sandboxOAuth && !options.staging) throw new Error("Sandbox OAuth is unavailable in production");
  if (options.production && options.sandboxWebhook && !options.staging) throw new Error("Sandbox webhooks are unavailable in production");
  if (options.sandboxExchange && !options.sandboxOAuth) throw new Error("Sandbox exchange requires OAuth");
  if (options.sandboxOAuthStatus && (!options.staging || !options.sandboxExchange)) {
    throw new Error("Sandbox connection status requires staging exchange");
  }
  if (options.production && !options.loginRateLimitStore) throw new Error("Production requires a shared login rate-limit store");
  if (options.liveOAuth && (!options.production || options.staging)) throw new Error("Live Stripe OAuth requires production");
  if (options.production && (options.connectOnboarding || options.liveOAuth || options.livePublication || options.ownerCheckout) && !options.connectRateLimitStore) {
    throw new Error("Stripe Connect requires a shared rate-limit store");
  }
  if (options.checkoutPilot && !options.staging) throw new Error("Checkout pilot requires staging");
  if (options.liveCheckout && (!options.production || options.staging)) throw new Error("Live checkout requires production");
  if (options.production && options.storefront && !options.storefront.rateLimitStore) {
    throw new Error("Production requires a shared storefront rate-limit store");
  }
  const app = express();
  app.disable("x-powered-by");
  if (options.production || options.sandboxOAuth) app.set("trust proxy", 1);
  app.use("/api", (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });
  if (options.staging) {
    app.use((req, res, next) => {
      if (!req.secure) { res.status(403).json({ error: "HTTPS_REQUIRED" }); return; }
      next();
    });
  }
  app.use(helmet(options.ownerCheckout ? { contentSecurityPolicy: { directives: {
    scriptSrc: ["'self'", "https://js.stripe.com", "https://*.js.stripe.com", "https://checkout.stripe.com"],
    frameSrc: ["https://js.stripe.com", "https://*.js.stripe.com", "https://hooks.stripe.com", "https://checkout.stripe.com"],
    connectSrc: ["'self'", "https://api.stripe.com", "https://checkout.stripe.com"],
    imgSrc: ["'self'", "data:", "https://*.stripe.com"]
  } } } : {}));
  if (options.sandboxWebhook) {
    const webhook = options.sandboxWebhook;
    app.post("/api/stripe/webhooks/sandbox", (req, res, next) => {
      const encoding = req.get("content-encoding");
      if (encoding && encoding.toLowerCase() !== "identity") {
        res.status(415).json({ error: "UNSUPPORTED_CONTENT_ENCODING" }); return;
      }
      next();
    }, express.raw({ type: "application/json", limit: "256kb", inflate: false }), (req, res) => {
      if (!req.is("application/json") || !Buffer.isBuffer(req.body) ||
          !webhook.verify(req.body, req.get("stripe-signature") ?? "")) {
        res.status(400).json({ error: "INVALID_WEBHOOK" }); return;
      }
      res.status(503).json({ error: "WEBHOOK_PROCESSING_UNAVAILABLE" });
    });
  }
  if (options.checkoutWebhook) {
    const webhook = options.checkoutWebhook;
    app.post("/api/stripe/webhooks/checkout/:connectionId", (req, res, next) => {
      const encoding = req.get("content-encoding");
      if (encoding && encoding.toLowerCase() !== "identity") {
        res.status(415).json({ error: "UNSUPPORTED_CONTENT_ENCODING" }); return;
      }
      next();
    }, express.raw({ type: "application/json", limit: "256kb", inflate: false }), async (req, res) => {
      if (!req.is("application/json") || !Buffer.isBuffer(req.body) ||
          typeof req.params.connectionId !== "string" ||
          !z.string().uuid().safeParse(req.params.connectionId).success) {
        res.status(400).json({ error: "INVALID_WEBHOOK" }); return;
      }
      const outcome = await webhook.accept(req.params.connectionId, req.body, req.get("stripe-signature") ?? "");
      if (outcome === "inserted" || outcome === "duplicate") { res.sendStatus(204); return; }
      if (outcome === "invalid") { res.status(400).json({ error: "INVALID_WEBHOOK" }); return; }
      console.error("Checkout webhook processing unavailable", outcome);
      res.status(503).json({ error: "WEBHOOK_PROCESSING_UNAVAILABLE" });
    });
  }
  app.use(express.json({ limit: "16kb" }));
  if (options.checkoutPilot) app.use("/api/checkout/pilot", checkoutPilotRouter(options.checkoutPilot));
  if (options.liveCheckout) app.use("/api/checkout/live", checkoutPilotRouter({ ...options.liveCheckout, mode: "LIVE" }));
  app.get("/health/live", (_req, res) => { res.json({ status: "ok" }); });
  app.get("/health/ready", async (_req, res) => {
    try {
      await options.repository.checkHealth();
      res.json({ status: "ok" });
    } catch {
      console.error("Readiness check failed");
      res.status(503).json({ status: "unavailable" });
    }
  });
  app.use(session({
    name: "kuzushi.sid",
    secret: options.secret,
    store: options.store,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: options.production || !!options.sandboxOAuth, sameSite: "lax", maxAge: sessionLifetimeMs }
  }));
  app.use("/api", (req, res, next) => {
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      if (req.get("origin") !== options.origin || !req.is("application/json")) {
        res.status(403).json({ error: "FORBIDDEN_ORIGIN" });
        return;
      }
    }
    next();
  });
  app.use("/api", async (req, res, next) => {
    const publicPaths = ["/login", "/logout", "/features", "/mfa/status", "/password-reset/request", "/password-reset/confirm"];
    if (req.session.userId && !publicPaths.includes(req.path)) {
      if (options.mfa && !req.session.mfaVerified) {
        res.status(401).json({ error: "UNAUTHENTICATED" }); return;
      }
      if (!options.mfa && await options.repository.hasMfaAuthenticator(req.session.userId)) {
        console.error("MFA is unavailable for an enrolled account");
        res.status(503).json({ error: "MFA_UNAVAILABLE" }); return;
      }
    }
    next();
  });

  const passwordAttemptLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    store: options.loginRateLimitStore,
    passOnStoreError: false,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) => { res.status(429).json({ error: "RATE_LIMITED" }); }
  });

  app.get("/api/features", (_req, res) => {
    res.json({ passwordRecovery: !!options.passwordRecovery, mfa: !!options.mfa });
  });
  if (options.passwordRecovery) {
    const recovery = options.passwordRecovery;
    app.post("/api/password-reset/request", passwordAttemptLimiter, async (req, res) => {
      const parsed = z.object({ email: emailSchema, language: z.enum(["en", "es"]) }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      await recovery.request(parsed.data.email, parsed.data.language);
      res.status(202).json({ ok: true });
    });
    app.post("/api/password-reset/confirm", passwordAttemptLimiter, async (req, res) => {
      const parsed = z.object({
        token: z.string().regex(/^[a-f0-9]{64}$/), newPassword: passwordSchema
      }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      if (!await recovery.redeem(parsed.data.token, parsed.data.newPassword)) {
        res.status(400).json({ error: "INVALID_RESET" }); return;
      }
      res.json({ ok: true });
    });
  }

  async function completeSignIn(req: Request, user: User, version: number, mfaVerified: boolean) {
    await new Promise<void>((resolve, reject) => {
      req.session.regenerate((error) => error ? reject(error) : resolve());
    });
    req.session.userId = user.id;
    req.session.authenticatedAt = Date.now();
    req.session.authVersion = version;
    req.session.mfaVerified = mfaVerified;
    await new Promise<void>((resolve, reject) => {
      req.session.save((error) => error ? reject(error) : resolve());
    });
    try {
      await options.repository.recordLoginAttempt(user.id, true);
    } catch (error) {
      await new Promise<void>((resolve) => req.session.destroy((cleanupError) => {
        if (cleanupError) console.error("Login session cleanup failed");
        resolve();
      }));
      throw error;
    }
  }
  async function pendingUser(req: Request) {
    const pending = req.session.mfaPending;
    if (!pending || !Number.isFinite(pending.startedAt) ||
        !options.mfa || pending.keyFingerprint !== options.mfa.keyFingerprint ||
        Date.now() - pending.startedAt < 0 || Date.now() - pending.startedAt >= 10 * 60 * 1000) return null;
    const user = await options.repository.findUserById(pending.userId);
    return user && user.sessionVersion === pending.version ? { user, pending } : null;
  }

  app.get("/api/mfa/status", async (req, res) => {
    const pending = options.mfa && await pendingUser(req);
    const mfa = pending && options.mfa
      ? await options.mfa.isEnrolled(pending.user.id) ? "challenge"
        : pending.pending.recoveryRequired && !pending.pending.recoveryProof ? "recovery" : "setup"
      : null;
    res.json({ mfa });
  });
  if (options.mfa) {
    const mfa = options.mfa;
    app.post("/api/mfa/setup", passwordAttemptLimiter, async (req, res) => {
      const state = await pendingUser(req);
      if (!state) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      if (state.pending.recoveryRequired && !state.pending.recoveryProof) {
        res.status(403).json({ error: "MFA_RECOVERY_REQUIRED" }); return;
      }
      if (state.pending.recoveryRequired && !await mfa.recoveryProofValid(state.user.id, state.pending.recoveryProof)) {
        res.status(400).json({ error: "INVALID_RECOVERY_CODE" }); return;
      }
      if (await mfa.isEnrolled(state.user.id)) { res.status(409).json({ error: "MFA_ALREADY_ENROLLED" }); return; }
      const enrollment = mfa.prepareEnrollment(state.user.id, state.user.email);
      state.pending.pendingSecret = enrollment.pendingSecret;
      await new Promise<void>((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
      res.json({ secret: enrollment.secret });
    });
    app.post("/api/mfa/confirm", passwordAttemptLimiter, async (req, res) => {
      const state = await pendingUser(req);
      if (!state) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const parsed = z.object({ code: z.string().regex(/^[0-9]{6}$/) }).strict().safeParse(req.body);
      if (!parsed.success || !state.pending.pendingSecret) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      const result = await mfa.enroll(
        state.user.id, state.pending.version, state.pending.pendingSecret, parsed.data.code, state.pending.recoveryProof
      );
      if (!result) {
        const expired = state.pending.recoveryRequired &&
          !await mfa.recoveryProofValid(state.user.id, state.pending.recoveryProof);
        res.status(400).json({ error: expired ? "INVALID_RECOVERY_CODE" : "INVALID_MFA" }); return;
      }
      await completeSignIn(req, state.user, result.sessionVersion, true);
      res.json({ user: { id: state.user.id, email: state.user.email, role: state.user.role }, backupCodes: result.backupCodes });
    });
    app.post("/api/mfa/verify", passwordAttemptLimiter, async (req, res) => {
      const state = await pendingUser(req);
      if (!state) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const parsed = z.object({ code: z.string().min(1).max(64) }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      if (!await mfa.verify(state.user.id, state.pending.version, parsed.data.code)) {
        res.status(400).json({ error: "INVALID_MFA" }); return;
      }
      await completeSignIn(req, state.user, state.pending.version, true);
      res.json({ user: { id: state.user.id, email: state.user.email, role: state.user.role } });
    });
    app.post("/api/mfa/backup-codes", passwordAttemptLimiter, async (req, res) => {
      const user = await currentUser(options.repository, req.session);
      if (!user || !req.session.mfaVerified) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const parsed = z.object({ code: z.string().min(1).max(64) }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      const codes = await mfa.replaceBackupCodes(user.id, user.sessionVersion, parsed.data.code);
      if (!codes) { res.status(400).json({ error: "INVALID_MFA" }); return; }
      res.json({ backupCodes: codes });
    });
    app.post("/api/mfa/recovery", passwordAttemptLimiter, async (req, res) => {
      const state = await pendingUser(req);
      if (!state) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const parsed = z.object({ code: z.string().regex(/^[a-f0-9]{64}$/i).transform((value) => value.toLowerCase()) }).strict().safeParse(req.body);
      if (!parsed.success || !state.pending.recoveryRequired) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      const proof = await mfa.verifyRecoveryCode(state.user.id, state.pending.version, parsed.data.code);
      if (!proof) { res.status(400).json({ error: "INVALID_RECOVERY_CODE" }); return; }
      state.pending.recoveryProof = proof;
      await new Promise<void>((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
      res.json({ mfa: "setup" });
    });
    app.post("/api/admin/mfa-recovery", passwordAttemptLimiter, async (req, res) => {
      const actor = await currentUser(options.repository, req.session);
      if (!actor || !req.session.mfaVerified) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      if (actor.role !== "ADMIN") { res.status(403).json({ error: "FORBIDDEN" }); return; }
      const parsed = z.object({
        email: emailSchema, code: z.string().min(1).max(64), identityVerified: z.literal(true)
      }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      const result = await mfa.issueRecovery(actor.id, actor.sessionVersion, parsed.data.email, parsed.data.code);
      if (result.status === "unauthenticated") { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      if (result.status === "invalid_target") { res.status(400).json({ error: "INVALID_RECOVERY_TARGET" }); return; }
      if (result.status === "invalid_mfa") { res.status(400).json({ error: "INVALID_MFA" }); return; }
      res.json({ recoveryCode: result.recoveryCode });
    });
  }

  app.post("/api/login", passwordAttemptLimiter, async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
    const user = await options.repository.findUserByEmail(parsed.data.email);
    const valid = await verifyPassword(parsed.data.password, user?.passwordHash ?? dummyHash);
    if (!user || !valid) {
      await options.repository.recordLoginAttempt(user?.id ?? null, false);
      res.status(401).json({ error: "INVALID_CREDENTIALS" }); return;
    }
    if (passwordNeedsUpgrade(user.passwordHash)) {
      const updated = await options.repository.upgradePasswordHash(user.id, user.passwordHash, await hashPassword(parsed.data.password));
      if (!updated) {
        await options.repository.recordLoginAttempt(user.id, false);
        res.status(401).json({ error: "INVALID_CREDENTIALS" }); return;
      }
    }
    if (!options.mfa && await options.repository.hasMfaAuthenticator(user.id)) {
      console.error("MFA is unavailable for an enrolled account");
      res.status(503).json({ error: "MFA_UNAVAILABLE" }); return;
    }
    if (options.mfa) {
      const enrolled = await options.mfa.isEnrolled(user.id);
      const recoveryRequired = !enrolled && await options.mfa.requiresRecovery(user.id);
      await new Promise<void>((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
      req.session.mfaPending = {
        userId: user.id, version: user.sessionVersion, startedAt: Date.now(),
        keyFingerprint: options.mfa.keyFingerprint, recoveryRequired
      };
      await new Promise<void>((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
      res.json({ mfa: enrolled ? "challenge" : recoveryRequired ? "recovery" : "setup" }); return;
    }
    await completeSignIn(req, user, user.sessionVersion, false);
    res.json({ user: { id: user.id, email: user.email, role: user.role } });
  });

  app.get("/api/me", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    res.json({ user: { id: user.id, email: user.email, role: user.role } });
  });
  app.post("/api/logout", (req, res, next) => {
    req.session.destroy((error) => {
      if (error) { next(error); return; }
      res.clearCookie("kuzushi.sid", { httpOnly: true, secure: options.production || !!options.sandboxOAuth, sameSite: "lax" });
      res.json({ ok: true });
    });
  });
  app.post("/api/password", passwordAttemptLimiter, async (req, res, next) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    const parsed = passwordChangeSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
    if (!await verifyPassword(parsed.data.currentPassword, user.passwordHash)) {
      res.status(401).json({ error: "CURRENT_PASSWORD_INVALID" }); return;
    }
    if (await verifyPassword(parsed.data.newPassword, user.passwordHash)) {
      res.status(400).json({ error: "PASSWORD_UNCHANGED" }); return;
    }
    const updated = await options.repository.changePassword(
      user.id, user.passwordHash, await hashPassword(parsed.data.newPassword)
    );
    if (!updated) { res.status(409).json({ error: "CREDENTIALS_CHANGED" }); return; }
    req.session.destroy((error) => {
      if (error) { next(error); return; }
      res.clearCookie("kuzushi.sid", { httpOnly: true, secure: options.production || !!options.sandboxOAuth, sameSite: "lax" });
      res.json({ ok: true });
    });
  });
  app.get("/api/businesses", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    const businesses = await options.repository.listBusinesses(user);
    const sandboxOAuth = options.sandboxOAuth;
    const liveOAuth = options.liveOAuth;
    res.json({
      ...(options.connectOnboarding && user.role === "USER" ? { connectOnboardingAvailable: true } : {}),
      businesses: sandboxOAuth
        ? await Promise.all(businesses.map(async (business) => {
          if (!sandboxOAuth.isEnabledForBusiness(business.id)) return business;
          const status = await options.sandboxOAuthStatus?.(user, business.id);
          return {
            ...business, sandboxOAuthAvailable: !status || status === "available",
            ...(status ? { sandboxOAuthStatus: status } : {})
          };
        }))
        : liveOAuth && user.role === "USER" ? await Promise.all(businesses.map(async (business) => ({
          ...business, liveOAuthStatus: await liveOAuth.status(user, business.id)
        }))) : businesses
    });
  });
  const connectLimiter = options.connectOnboarding || options.liveOAuth || options.livePublication || options.ownerCheckout ? rateLimit({
    windowMs: 15 * 60 * 1000, limit: 30, store: options.connectRateLimitStore,
    keyGenerator: (req) => `stripe-connect:${ipKeyGenerator(req.ip ?? "unknown")}`
  }) : undefined;
  if (options.liveOAuth && connectLimiter) {
    const oauth = options.liveOAuth;
    app.post<{ id: string }>("/api/businesses/:id/stripe/oauth/live", connectLimiter, async (req, res) => {
      if (!req.secure) { res.status(403).json({ error: "HTTPS_REQUIRED" }); return; }
      const actor = await currentUser(options.repository, req.session);
      if (!actor) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const authorizationUrl = await oauth.start(actor, req.sessionID, req.params.id);
      if (!authorizationUrl) { res.status(409).json({ error: "STRIPE_CONNECTION_UNAVAILABLE" }); return; }
      res.json({ authorizationUrl });
    });
    app.post("/api/stripe/oauth/live/complete", connectLimiter, async (req, res) => {
      res.set("Referrer-Policy", "no-referrer");
      if (!req.secure) { res.status(403).json({ error: "HTTPS_REQUIRED" }); return; }
      const result = z.object({ state: z.string().length(43), code: z.string().min(1).max(2048).optional() })
        .strict().safeParse(req.body);
      let connected = false;
      try {
        if (result.success) {
          connected = await oauth.finish(req.session, req.sessionID, result.data.state, result.data.code);
        }
      } catch {
        console.error("Live Stripe OAuth callback failed");
      }
      res.redirect(303, `${options.origin}/?stripe_oauth=${connected ? "live_connected" : "live_failed"}`);
    });
  }
  if (options.connectOnboarding && connectLimiter) {
    const connect = options.connectOnboarding;
    const path = "/api/businesses/:id/stripe/connect";
    const authorized = async (req: Request, id: string) => {
      const actor = await currentUser(options.repository, req.session);
      return actor?.role === "USER" && !!await options.repository.findBusiness(actor, id);
    };
    app.get<{ id: string }>(path, connectLimiter, async (req, res) => {
      if (!await authorized(req, req.params.id)) { res.status(404).json({ error: "NOT_FOUND" }); return; }
      res.json({ status: await connect.status(req.params.id) });
    });
    app.post<{ id: string }>(path, connectLimiter, async (req, res) => {
      const id = req.params.id;
      if (!await authorized(req, id)) { res.status(404).json({ error: "NOT_FOUND" }); return; }
      const authorizationUrl = await connect.start(id, () => authorized(req, id));
      if (!authorizationUrl) { res.status(409).json({ error: "STRIPE_CONNECTION_UNAVAILABLE" }); return; }
      res.json({ authorizationUrl });
    });
  }
  app.get("/api/businesses/:id", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    const business = await options.repository.findBusiness(user, req.params.id);
    if (!business) { res.status(404).json({ error: "NOT_FOUND" }); return; }
    res.json({ business });
  });
  app.post("/api/businesses", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    if (user.role !== "ADMIN") { res.status(403).json({ error: "FORBIDDEN" }); return; }
    const parsed = businessSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
    if (await options.repository.findUserByEmail(parsed.data.email)) {
      res.status(409).json({ error: "EMAIL_IN_USE" }); return;
    }
    try {
      const business = await options.repository.createBusinessWithOwner(
        user, parsed.data.name, parsed.data.email, await hashPassword(parsed.data.password)
      );
      res.status(201).json({ business });
    } catch (error) {
      if (error instanceof EmailInUseError) {
        res.status(409).json({ error: "EMAIL_IN_USE" }); return;
      }
      if (error instanceof AuthorizationChangedError) {
        res.status(401).json({ error: "UNAUTHENTICATED" }); return;
      }
      throw error;
    }
  });
  app.get("/api/businesses/:id/product-drafts", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    if (!await options.repository.findBusiness(user, req.params.id)) { res.status(404).json({ error: "NOT_FOUND" }); return; }
    const drafts = await options.repository.listProductDrafts(user, req.params.id);
    const publications = options.livePublication && user.role === "USER"
      ? await options.livePublication.list(req.params.id) : undefined;
    res.json({ drafts, publications });
  });
  if (options.livePublication && connectLimiter) {
    const publication = options.livePublication;
    app.post<{ id: string; productId: string }>("/api/businesses/:id/product-drafts/:productId/publish",
      connectLimiter, async (req, res) => {
        const user = await currentUser(options.repository, req.session);
        if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
        const { id, productId } = req.params;
        if (user.role !== "USER" || !await options.repository.findBusiness(user, id)) {
          res.status(404).json({ error: "NOT_FOUND" }); return;
        }
        if (!z.uuid().safeParse(productId).success) {
          res.status(400).json({ error: "INVALID_INPUT" }); return;
        }
        try {
          await publication.publish(user, id, productId);
          res.json({ published: true });
        } catch (error) {
          if (error instanceof AuthorizationChangedError) {
            res.status(401).json({ error: "UNAUTHENTICATED" }); return;
          }
          if (!(error instanceof PublicationError)) throw error;
          res.status(error.code === "PREPARATION_FAILED" ? 503 : 409)
            .json({ error: `PUBLICATION_${error.code}` });
        }
      });
  }
  if (options.ownerCheckout && connectLimiter) {
    const checkout = options.ownerCheckout;
    const owner = async (req: Request, id: string) => {
      const user = await currentUser(options.repository, req.session);
      return user?.role === "USER" && await options.repository.findBusiness(user, id) ? user : null;
    };
    app.get<{ id: string }>("/api/businesses/:id/live-orders", async (req, res) => {
      if (!await owner(req, req.params.id)) {
        res.status(req.session.userId ? 404 : 401).json({ error: req.session.userId ? "NOT_FOUND" : "UNAUTHENTICATED" });
        return;
      }
      res.set("Cache-Control", "no-store").json({ orders: await checkout.list(req.params.id) });
    });
    app.post<{ id: string; productId: string }>("/api/businesses/:id/product-drafts/:productId/checkout",
      connectLimiter, async (req, res) => {
        const { id, productId } = req.params;
        const actor = await owner(req, id);
        if (!actor) {
          res.status(req.session.userId ? 404 : 401).json({ error: req.session.userId ? "NOT_FOUND" : "UNAUTHENTICATED" });
          return;
        }
        const parsed = z.object({ requestId: z.uuid() }).strict().safeParse(req.body);
        if (!parsed.success || !z.uuid().safeParse(productId).success) {
          res.status(400).json({ error: "INVALID_INPUT" }); return;
        }
        try {
          const session = await checkout.create(actor, id, productId, parsed.data.requestId);
          res.set("Cache-Control", "no-store").status(201).json(session);
        } catch (error) {
          if (!(error instanceof CheckoutServiceError)) throw error;
          res.status(error.code === "UNAVAILABLE" ? 409 : 503).json({ error: `CHECKOUT_${error.code}` });
        }
      });
  }
  app.post("/api/businesses/:id/product-drafts", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    const parsed = productDraftSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
    const draft = await options.repository.createProductDraft(user, req.params.id, parsed.data);
    if (!draft) { res.status(404).json({ error: "NOT_FOUND" }); return; }
    res.status(201).json({ draft });
  });
  app.put("/api/businesses/:id/product-drafts/:productId", async (req, res) => {
    const user = await currentUser(options.repository, req.session);
    if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
    const parsed = productDraftSchema.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
    const draft = await options.repository.updateProductDraft(user, req.params.id, req.params.productId, parsed.data);
    if (!draft) { res.status(404).json({ error: "NOT_FOUND" }); return; }
    res.json({ draft });
  });
  if (options.storefront) {
    const { proposals, rateLimitStore } = options.storefront;
    const path = "/api/businesses/:id/storefront";
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, limit: 20, store: rateLimitStore,
      keyGenerator: (req) => `storefront:ip:${ipKeyGenerator(req.ip ?? "")}`,
      standardHeaders: "draft-7", legacyHeaders: false,
      handler: (_req, res) => { res.status(429).json({ error: "RATE_LIMITED" }); }
    });
    app.get(path, async (req, res) => {
      const user = await currentUser(options.repository, req.session);
      if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      if (!await options.repository.findBusiness(user, req.params.id)) {
        res.status(404).json({ error: "NOT_FOUND" }); return;
      }
      res.json({
        ...storefrontResponse(await proposals.find(user, req.params.id)),
        ...(options.checkoutPilot?.businessId === req.params.id ? { pilotConfigured: true } : {})
      });
    });
    app.get(`${path}/pilot-orders`, async (req, res) => {
      const user = await currentUser(options.repository, req.session);
      if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const pilot = options.checkoutPilot;
      if (!pilot || pilot.businessId !== req.params.id || !await options.repository.findBusiness(user, req.params.id)) {
        res.status(404).json({ error: "NOT_FOUND" }); return;
      }
      res.json({ orders: await pilot.listOrders() });
    });
    app.put<{ id: string }>(path, limiter, async (req, res) => {
      const user = await currentUser(options.repository, req.session);
      if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const parsed = storefrontSetupSchema.safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      const proposal = await proposals.save(user, req.params.id, parsed.data);
      if (!proposal) { res.status(404).json({ error: "NOT_FOUND" }); return; }
      res.json(storefrontResponse(proposal));
    });
    app.post<{ id: string }>(`${path}/verify`, limiter, async (req, res) => {
      const user = await currentUser(options.repository, req.session);
      if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      const parsed = z.object({ revision: z.uuid() }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      if (!await options.repository.findBusiness(user, req.params.id)) {
        res.status(404).json({ error: "NOT_FOUND" }); return;
      }
      const proposal = await proposals.verify(user, req.params.id, parsed.data.revision);
      if (!proposal) { res.status(409).json({ error: "STOREFRONT_DNS_UNVERIFIED" }); return; }
      res.json(storefrontResponse(proposal));
    });
    app.post<{ id: string }>(`${path}/approve-test`, limiter, async (req, res) => {
      const user = await currentUser(options.repository, req.session);
      if (!user) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
      if (user.role !== "ADMIN") { res.status(403).json({ error: "FORBIDDEN" }); return; }
      const parsed = z.object({ revision: z.uuid() }).strict().safeParse(req.body);
      if (!parsed.success) { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      const proposal = await proposals.approveTest(user, req.params.id, parsed.data.revision);
      if (!proposal) { res.status(409).json({ error: "STOREFRONT_APPROVAL_UNAVAILABLE" }); return; }
      res.json(storefrontResponse(proposal));
    });
  }
  if (options.sandboxOAuth) {
    const oauth = options.sandboxOAuth;
    app.use(["/api/stripe/oauth/sandbox/callback", "/api/businesses/:id/stripe/oauth/sandbox"], (_req, res, next) => {
      res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
      next();
    });
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false,
      handler: (_req, res) => { res.status(429).json({ error: "RATE_LIMITED" }); }
    });
    app.post("/api/businesses/:id/stripe/oauth/sandbox", limiter, async (req, res) => {
      res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
      if (typeof req.params.id !== "string") { res.status(400).json({ error: "INVALID_INPUT" }); return; }
      if (options.sandboxOAuthStatus && oauth.isEnabledForBusiness(req.params.id)) {
        const actor = await currentUser(options.repository, req.session);
        if (!actor) { res.status(401).json({ error: "UNAUTHENTICATED" }); return; }
        if (await options.sandboxOAuthStatus(actor, req.params.id) !== "available") {
          res.status(409).json({ error: "STRIPE_CONNECTION_UNAVAILABLE" }); return;
        }
      }
      const result = await oauth.initiate(req.session, req.sessionID, req.params.id);
      if ("error" in result) {
        const status = result.error === "UNAUTHENTICATED" ? 401 : result.error === "NOT_FOUND" ? 404 : 409;
        res.status(status).json({ error: result.error }); return;
      }
      res.json({ authorizationUrl: result.url });
    });
    app.get("/api/stripe/oauth/sandbox/callback", limiter, async (req, res) => {
      res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
      const query = new URL(req.originalUrl, "https://local.invalid").searchParams;
      const states = query.getAll("state");
      const codes = query.getAll("code");
      const errors = query.getAll("error");
      let outcome = "failed";
      if (states.length === 1 && codes.length === 1 && errors.length === 0 &&
          codes[0].length > 0 && codes[0].length <= 2048) {
        if (options.sandboxExchange) {
          const result = await options.sandboxExchange.verify(req.session, req.sessionID, states[0], codes[0]);
          if (result.ok) outcome = result.connected ? "connected" : "identity_verified";
          else console.error("Sandbox OAuth exchange failed", result.error);
        } else if (await oauth.callback(req.session, req.sessionID, states[0])) {
          outcome = "validated";
        }
      }
      if (outcome === "failed" && states.length === 1 && codes.length === 0 && errors.length === 1) {
        await oauth.callback(req.session, req.sessionID, states[0]);
      }
      res.redirect(303, `${options.origin}/?stripe_oauth=${outcome}`);
    });
  }
  const errors: ErrorRequestHandler = (error, _req, res, _next) => {
    if (error instanceof MfaRateLimitError) {
      res.status(429).json({ error: "RATE_LIMITED" }); return;
    }
    if (error instanceof AuthorizationChangedError) {
      res.status(401).json({ error: "UNAUTHENTICATED" }); return;
    }
    if (error instanceof PasswordWorkLimitError) {
      console.error("Password hashing capacity exhausted");
      res.set("Retry-After", "2").status(503).json({ error: "PASSWORD_CAPACITY" }); return;
    }
    if (error instanceof SyntaxError && "body" in error) {
      res.status(400).json({ error: "INVALID_INPUT" }); return;
    }
    if (error instanceof Error && "status" in error && error.status === 413) {
      res.status(413).json({ error: "INVALID_INPUT" }); return;
    }
    console.error("Request failed");
    res.status(500).json({ error: "SERVER_ERROR" });
  };
  app.use(errors);
  return app;
}
