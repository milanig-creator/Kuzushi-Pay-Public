import "dotenv/config";
import { z } from "zod";

const checkoutPilotSchema = z.object({
  businessId: z.uuid(), connectionId: z.uuid(), publicationId: z.uuid(), revision: z.uuid(),
  accountId: z.string().regex(/^acct_[A-Za-z0-9]+$/),
  origin: z.url().refine((value) => URL.parse(value)?.origin === value && value.startsWith("https://")),
  projectId: z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/),
  publishableKey: z.string().regex(/^pk_test_[A-Za-z0-9]{10,}$/)
}).strict();

const liveCheckoutSchema = checkoutPilotSchema.omit({ projectId: true }).extend({
  publishableKey: z.string().regex(/^pk_live_[A-Za-z0-9]{10,}$/)
});

const schema = z.object({
  DATABASE_URL: z.string().url(),
  SESSION_SECRET: z.string().min(32),
  APP_ORIGIN: z.string().url(),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  APP_ENV: z.enum(["development", "staging", "production"]).default("production"),
  STRIPE_CONNECT_PLATFORM_KEY: z.string().regex(/^sk_(test|live)_[A-Za-z0-9]+$/).optional(),
  STRIPE_OAUTH_LIVE_CLIENT_ID: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/).optional(),
  STRIPE_OAUTH_LIVE_PUBLIC_CLIENT_ID: z.string().regex(/^ca_[A-Za-z0-9]{8,125}$/).optional(),
  STRIPE_OAUTH_LIVE_GCP_PROJECT_ID: z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/).optional(),
  STRIPE_OAUTH_LIVE_KEY_SECRET_ID: z.string().regex(/^kp-stripe-oauth-developer-[a-f0-9]{32}$/).optional(),
  STRIPE_OAUTH_LIVE_KEY_SECRET_VERSION: z.string().regex(/^[1-9][0-9]*$/).optional(),
  STRIPE_OAUTH_LIVE_TEST_CHANNEL: z.string().regex(/^chnlink_[A-Za-z0-9_-]{8,128}$/).optional(),
  STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID: z.uuid().optional(),
  CHECKOUT_LIVE_PREVIEW_TOKEN: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  CHECKOUT_LIVE_CONFIG: z.string().transform((value, context) => {
    try {
      const parsed = liveCheckoutSchema.safeParse(JSON.parse(value));
      if (parsed.success) return parsed.data;
    } catch {
      // Report malformed configuration without echoing its contents.
    }
    context.addIssue({ code: "custom", message: "Invalid live checkout configuration" });
    return z.NEVER;
  }).optional(),
  CHECKOUT_PILOT_CONFIG: z.string().transform((value, context) => {
    try {
      const parsed = checkoutPilotSchema.safeParse(JSON.parse(value));
      if (parsed.success) return parsed.data;
    } catch {
      // Report malformed configuration without echoing its contents.
    }
    context.addIssue({ code: "custom", message: "Invalid checkout pilot configuration" });
    return z.NEVER;
  }).optional(),
  CHECKOUT_PILOT_WEBHOOK_SECRET: z.string().regex(/^whsec_[A-Za-z0-9]{12,}$/).optional(),
  MFA_ENABLED: z.enum(["true", "false"]).default("false"),
  MFA_KEY: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  PASSWORD_RESET_ENABLED: z.enum(["true", "false"]).default("false"),
  PASSWORD_RESET_KEY: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  SMTP_HOST: z.string().min(1).optional(),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  SMTP_SECURE: z.enum(["true", "false"]).optional(),
  SMTP_USER: z.string().min(1).optional(),
  SMTP_PASSWORD: z.string().min(1).optional(),
  SMTP_FROM: z.string().email().max(254).optional(),
  STRIPE_OAUTH_SANDBOX_ENABLED: z.enum(["true", "false"]).default("false"),
  STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED: z.enum(["true", "false"]).default("false"),
  STRIPE_OAUTH_SANDBOX_INSTALL_URL: z.string().optional(),
  STRIPE_OAUTH_SANDBOX_REDIRECT_URI: z.string().optional(),
  STRIPE_OAUTH_SANDBOX_BUSINESS_ID: z.string().uuid().optional(),
  STRIPE_OAUTH_SANDBOX_EXPECTED_ACCOUNT_ID: z.string().regex(/^acct_[A-Za-z0-9]+$/).optional(),
  STRIPE_OAUTH_SANDBOX_SECRET_ID: z.string().regex(/^kp-stripe-oauth-test-[a-f0-9]{32}$/).optional(),
  STRIPE_OAUTH_SANDBOX_SECRET_VERSION: z.string().regex(/^[1-9][0-9]*$/).optional(),
  STRIPE_OAUTH_SANDBOX_TOKEN_SECRET_ID: z.string().regex(/^kp-stripe-oauth-test-[a-f0-9]{32}$/).optional(),
  STRIPE_OAUTH_SANDBOX_GCP_PROJECT_ID: z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/).optional(),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000)
}).superRefine((value, context) => {
  const origin = new URL(value.APP_ORIGIN);
  const liveOAuth = [value.STRIPE_OAUTH_LIVE_CLIENT_ID, value.STRIPE_OAUTH_LIVE_GCP_PROJECT_ID,
    value.STRIPE_OAUTH_LIVE_KEY_SECRET_ID, value.STRIPE_OAUTH_LIVE_KEY_SECRET_VERSION];
  if (value.STRIPE_OAUTH_LIVE_PUBLIC_CLIENT_ID && liveOAuth.some((setting) => !setting)) {
    context.addIssue({ code: "custom", message: "The public Stripe OAuth client ID requires complete live OAuth configuration" });
  }
  if (liveOAuth.some(Boolean) && (value.APP_ENV !== "production" || liveOAuth.some((setting) => !setting))) {
    context.addIssue({ code: "custom", message: "Live Stripe OAuth requires production and complete configuration" });
  }
  if ((value.STRIPE_OAUTH_LIVE_TEST_CHANNEL || value.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID) &&
      (!value.STRIPE_OAUTH_LIVE_TEST_CHANNEL || !value.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID || liveOAuth.some((setting) => !setting))) {
    context.addIssue({ code: "custom", message: "External Stripe OAuth testing requires a channel, designated business, and complete live OAuth configuration" });
  }
  if (value.CHECKOUT_LIVE_CONFIG && (value.APP_ENV !== "production" || liveOAuth.some((setting) => !setting) ||
      (value.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID &&
       value.CHECKOUT_LIVE_CONFIG.businessId !== value.STRIPE_OAUTH_LIVE_TEST_BUSINESS_ID))) {
    context.addIssue({ code: "custom", message: "Live checkout requires production OAuth for the configured business" });
  }
  if (value.STRIPE_CONNECT_PLATFORM_KEY &&
      !(value.APP_ENV === "staging" && value.STRIPE_CONNECT_PLATFORM_KEY.startsWith("sk_test_") ||
        value.APP_ENV === "production" && value.STRIPE_CONNECT_PLATFORM_KEY.startsWith("sk_live_"))) {
    context.addIssue({ code: "custom", message: "Stripe Connect platform key must match the app environment" });
  }
  if ((value.CHECKOUT_PILOT_CONFIG || value.CHECKOUT_PILOT_WEBHOOK_SECRET) &&
      (value.APP_ENV !== "staging" || !value.CHECKOUT_PILOT_CONFIG || !value.CHECKOUT_PILOT_WEBHOOK_SECRET)) {
    context.addIssue({ code: "custom", message: "Checkout pilot requires staging, a test integration, and a webhook signing secret" });
  }
  if (value.APP_ENV !== "development" && value.NODE_ENV !== "production") {
    context.addIssue({ code: "custom", message: "Staging and production require NODE_ENV=production" });
  }
  if (value.SESSION_SECRET === "REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS") {
    context.addIssue({ code: "custom", message: "Replace the example session secret with a random value" });
  }
  if (value.MFA_ENABLED === "true" &&
      (!value.MFA_KEY || /^0+$/.test(value.MFA_KEY) || value.MFA_KEY === value.PASSWORD_RESET_KEY ||
       value.MFA_KEY === value.SESSION_SECRET)) {
    context.addIssue({ code: "custom", message: "MFA requires a dedicated random encryption key" });
  }
  if (value.MFA_ENABLED === "true" && value.APP_ENV === "production") {
    context.addIssue({ code: "custom", message: "MFA is available only for development or staging until production validation is complete" });
  }
  if (value.PASSWORD_RESET_ENABLED === "true" &&
      (!value.PASSWORD_RESET_KEY || !value.SMTP_HOST || !value.SMTP_PORT ||
       !value.SMTP_SECURE || !value.SMTP_FROM || (!!value.SMTP_USER !== !!value.SMTP_PASSWORD))) {
    context.addIssue({ code: "custom", message: "Password recovery requires an encryption key and complete TLS SMTP configuration" });
  }
  if (value.PASSWORD_RESET_KEY && /^0+$/.test(value.PASSWORD_RESET_KEY)) {
    context.addIssue({ code: "custom", message: "Password recovery requires a random encryption key" });
  }
  if (origin.origin !== value.APP_ORIGIN || !["http:", "https:"].includes(origin.protocol) ||
      (value.NODE_ENV === "production" && origin.protocol !== "https:")) {
    context.addIssue({ code: "custom", message: "APP_ORIGIN must be an exact HTTP(S) origin and HTTPS in production" });
  }
  if (value.STRIPE_OAUTH_SANDBOX_ENABLED === "true") {
    if (!((value.NODE_ENV === "development" && value.APP_ENV === "development") ||
          (value.NODE_ENV === "production" && value.APP_ENV === "staging")) || origin.protocol !== "https:" ||
        !value.STRIPE_OAUTH_SANDBOX_INSTALL_URL || !value.STRIPE_OAUTH_SANDBOX_REDIRECT_URI) {
      context.addIssue({ code: "custom", message: "Sandbox OAuth requires an explicitly designated development or staging environment, HTTPS origin, external test URL and HTTPS callback" });
    }
    if (value.APP_ENV === "staging" && !value.STRIPE_OAUTH_SANDBOX_BUSINESS_ID) {
      context.addIssue({ code: "custom", message: "Staging OAuth requires a designated test business" });
    }
  }
  if (value.STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED === "true" &&
      (value.STRIPE_OAUTH_SANDBOX_ENABLED !== "true" || value.APP_ENV !== "staging" ||
       value.NODE_ENV !== "production" || !value.STRIPE_OAUTH_SANDBOX_BUSINESS_ID ||
       !value.STRIPE_OAUTH_SANDBOX_EXPECTED_ACCOUNT_ID || !value.STRIPE_OAUTH_SANDBOX_SECRET_ID ||
       !value.STRIPE_OAUTH_SANDBOX_SECRET_VERSION || !value.STRIPE_OAUTH_SANDBOX_GCP_PROJECT_ID)) {
    context.addIssue({ code: "custom", message: "Sandbox exchange requires staging, OAuth, a designated business, expected test account, and a pinned test secret" });
  }
  if (value.STRIPE_OAUTH_SANDBOX_TOKEN_SECRET_ID &&
      (value.STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED !== "true" ||
        value.STRIPE_OAUTH_SANDBOX_TOKEN_SECRET_ID === value.STRIPE_OAUTH_SANDBOX_SECRET_ID)) {
    context.addIssue({ code: "custom", message: "Sandbox token storage requires staging exchange and a separate token secret" });
  }
});

export function parseConfig(environment: NodeJS.ProcessEnv) {
  return schema.parse(environment);
}

export function loadConfig() {
  return parseConfig(process.env);
}
