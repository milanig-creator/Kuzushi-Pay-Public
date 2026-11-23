import { describe, expect, it } from "vitest";
import { parseConfig } from "./config.js";

const base = {
  NODE_ENV: "production",
  APP_ENV: "staging",
  DATABASE_URL: "postgresql://test:test@localhost:5432/staging",
  SESSION_SECRET: "a-unique-test-secret-with-at-least-32-characters",
  APP_ORIGIN: "https://staging.example.com"
};
const oauth = {
  STRIPE_OAUTH_SANDBOX_ENABLED: "true",
  STRIPE_OAUTH_SANDBOX_INSTALL_URL: "https://marketplace.stripe.com/oauth/v2/authorize?client_id=client_test",
  STRIPE_OAUTH_SANDBOX_REDIRECT_URI: "https://staging.example.com/api/stripe/oauth/sandbox/callback",
  STRIPE_OAUTH_SANDBOX_BUSINESS_ID: "23f62c45-04fe-433d-b513-9c98532c3ed3"
};
const exchange = {
  STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED: "true",
  STRIPE_OAUTH_SANDBOX_EXPECTED_ACCOUNT_ID: "acct_expected",
  STRIPE_OAUTH_SANDBOX_SECRET_ID: `kp-stripe-oauth-test-${"a".repeat(32)}`,
  STRIPE_OAUTH_SANDBOX_SECRET_VERSION: "1",
  STRIPE_OAUTH_SANDBOX_GCP_PROJECT_ID: "staging-project"
};

describe("environment configuration", () => {
  it("gates MFA to development or staging with a dedicated key", () => {
    const mfa = { MFA_ENABLED: "true", MFA_KEY: "ab".repeat(32) };
    expect(() => parseConfig({ ...base, ...mfa })).not.toThrow();
    expect(() => parseConfig({ ...base, ...mfa, APP_ENV: "production" })).toThrow();
    expect(() => parseConfig({ ...base, MFA_ENABLED: "true" })).toThrow();
    expect(() => parseConfig({ ...base, ...mfa, MFA_KEY: "0".repeat(64) })).toThrow();
    expect(() => parseConfig({ ...base, ...mfa, PASSWORD_RESET_KEY: mfa.MFA_KEY })).toThrow();
    expect(() => parseConfig({ ...base, ...mfa, SESSION_SECRET: mfa.MFA_KEY })).toThrow();
  });
  it("requires production security settings for staging and production", () => {
    expect(() => parseConfig({ ...base, APP_ENV: "production" })).not.toThrow();
    expect(() => parseConfig({ ...base, APP_ENV: "production", NODE_ENV: "development" })).toThrow();
    expect(() => parseConfig({ ...base, APP_ENV: "production", NODE_ENV: "test" })).toThrow();
    expect(() => parseConfig({ ...base, APP_ENV: undefined, NODE_ENV: "development" })).toThrow();
    expect(() => parseConfig({ ...base, APP_ENV: "development", NODE_ENV: "development", APP_ORIGIN: "http://localhost:5173" })).not.toThrow();
  });
});

describe("staging OAuth configuration", () => {
  it("defaults both features off", () => {
    const config = parseConfig(base);
    expect(config.STRIPE_OAUTH_SANDBOX_ENABLED).toBe("false");
    expect(config.STRIPE_OAUTH_SANDBOX_EXCHANGE_ENABLED).toBe("false");
  });

  describe("password recovery configuration", () => {
    const smtp = {
      PASSWORD_RESET_ENABLED: "true",
      PASSWORD_RESET_KEY: "ab".repeat(32),
      SMTP_HOST: "smtp.example.com",
      SMTP_PORT: "587",
      SMTP_SECURE: "false",
      SMTP_USER: "sender@example.com",
      SMTP_PASSWORD: "test-password",
      SMTP_FROM: "sender@example.com"
    };
    it("defaults recovery off and requires a complete SMTP configuration", () => {
      expect(parseConfig(base).PASSWORD_RESET_ENABLED).toBe("false");
      expect(() => parseConfig({ ...base, ...smtp })).not.toThrow();
      expect(() => parseConfig({ ...base, ...smtp, SMTP_PASSWORD: undefined })).toThrow();
      expect(() => parseConfig({ ...base, ...smtp, PASSWORD_RESET_KEY: "0".repeat(64) })).toThrow();
      expect(() => parseConfig({ ...base, ...smtp, SMTP_FROM: undefined })).toThrow();
      expect(() => parseConfig({ ...base, ...smtp, SMTP_SECURE: undefined })).toThrow();
    });
  });
  it("requires explicit staging and all scoped test configuration", () => {
    expect(() => parseConfig({ ...base, ...oauth, ...exchange })).not.toThrow();
    expect(() => parseConfig({ ...base, ...oauth, ...exchange, APP_ENV: "production" })).toThrow();
    expect(() => parseConfig({ ...base, NODE_ENV: "development" })).toThrow();
    expect(() => parseConfig({ ...base, ...exchange })).toThrow();
    expect(() => parseConfig({ ...base, ...oauth, ...exchange, STRIPE_OAUTH_SANDBOX_SECRET_VERSION: "latest" })).toThrow();
    expect(() => parseConfig({ ...base, ...oauth, ...exchange, STRIPE_OAUTH_SANDBOX_BUSINESS_ID: "" })).toThrow();
    expect(() => parseConfig({ ...base, ...oauth, ...exchange, APP_ORIGIN: "http://staging.example.com" })).toThrow();
  });
});
