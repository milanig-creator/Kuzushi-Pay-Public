import type { SessionData } from "express-session";
import type { SecretManager, SecretVersion } from "../secrets/secret-manager.js";
import type { SandboxOAuthService } from "./oauth-sandbox.js";

type StateValidator = Pick<SandboxOAuthService, "callback">;
type CredentialReader = () => Promise<Uint8Array>;
type TokenExchange = (key: string, code: string) => Promise<unknown>;

export type StripeOAuthTokens = {
  accessToken: string;
  refreshToken: string;
  accountId: string;
  livemode: boolean;
  publishableKey?: string;
};

export function parseStripeOAuthTokens(response: unknown): StripeOAuthTokens | null {
  if (!response || typeof response !== "object" || !("livemode" in response) ||
      !("stripe_user_id" in response) || !("access_token" in response) || !("refresh_token" in response) ||
      typeof response.access_token !== "string" || !response.access_token ||
      typeof response.refresh_token !== "string" || !response.refresh_token ||
      typeof response.stripe_user_id !== "string" ||
      !/^acct_[A-Za-z0-9]+$/.test(response.stripe_user_id) || typeof response.livemode !== "boolean") {
    return null;
  }
  const key = "stripe_publishable_key" in response ? response.stripe_publishable_key : undefined;
  const keyPattern = response.livemode ? /^pk_live_[A-Za-z0-9]{10,}$/ : /^pk_test_[A-Za-z0-9]{10,}$/;
  return {
    accessToken: response.access_token,
    refreshToken: response.refresh_token,
    accountId: response.stripe_user_id,
    livemode: response.livemode,
    ...(typeof key === "string" && keyPattern.test(key) ? { publishableKey: key } : {})
  };
}

export type IdentityResult =
  | { ok: true; accountId: string; connected?: true }
  | { ok: false; error: "INVALID_STATE" | "INVALID_INPUT" | "CREDENTIAL_UNAVAILABLE" |
      "EXCHANGE_FAILED" | "INVALID_RESPONSE" | "LIVE_MODE" | "ACCOUNT_MISMATCH" | "BINDING_FAILED" };

export function encodeStripeOAuthTokens(tokens: StripeOAuthTokens, issuedAt?: number): Uint8Array {
  return Buffer.from(JSON.stringify({
    access_token: tokens.accessToken, refresh_token: tokens.refreshToken,
    stripe_user_id: tokens.accountId, livemode: tokens.livemode, issued_at: issuedAt,
    stripe_publishable_key: tokens.publishableKey
  }));
}

export function sandboxDeveloperCredential(secrets: Pick<SecretManager, "accessVersion">, reference: SecretVersion): CredentialReader {
  if (!/^kp-stripe-oauth-test-[a-f0-9]{32}$/.test(reference.secretId) ||
      !/^[1-9][0-9]*$/.test(reference.version)) {
    throw new Error("Invalid sandbox developer credential reference");
  }
  return () => secrets.accessVersion(reference);
}

async function requestStripeToken(key: string, body: URLSearchParams): Promise<unknown> {
  const response = await fetch("https://api.stripe.com/v1/oauth/token", {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${key}:`).toString("base64")}`,
      "content-type": "application/x-www-form-urlencoded",
      "stripe-version": "2026-10-28.endive"
    },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw new Error("Stripe exchange failed");
  if (!response.body) throw new Error("Stripe exchange response missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const part = await reader.read();
    if (part.done) break;
    length += part.value.byteLength;
    if (length > 65536) {
      await reader.cancel();
      throw new Error("Stripe exchange response too large");
    }
    chunks.push(part.value);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

export function exchangeWithStripe(key: string, code: string): Promise<unknown> {
  return requestStripeToken(key, new URLSearchParams({ grant_type: "authorization_code", code }));
}

export function refreshWithStripe(key: string, refreshToken: string): Promise<unknown> {
  return requestStripeToken(key, new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }));
}

export class SandboxIdentityExchange {
  constructor(
    runtime: "development" | "test" | "staging" | "production",
    private readonly state: StateValidator,
    private readonly readCredential: CredentialReader,
    private readonly expectedAccountId: string,
    private readonly exchange: TokenExchange = exchangeWithStripe,
    private readonly bind?: (session: Partial<SessionData>, tokens: StripeOAuthTokens) => Promise<boolean>
  ) {
    if (runtime === "production" || (process.env.NODE_ENV === "production" && runtime !== "staging")) {
      throw new Error("Sandbox identity exchange is unavailable in production");
    }
    if (!/^acct_[A-Za-z0-9]+$/.test(expectedAccountId)) throw new Error("Invalid expected account ID");
  }

  async verify(session: Partial<SessionData>, sessionId: string, state: string, code: string): Promise<IdentityResult> {
    if (!/^[A-Za-z0-9_-]{1,2048}$/.test(code)) return { ok: false, error: "INVALID_INPUT" };
    if (!await this.state.callback(session, sessionId, state)) return { ok: false, error: "INVALID_STATE" };

    let credential: Uint8Array;
    try {
      credential = await this.readCredential();
    } catch {
      return { ok: false, error: "CREDENTIAL_UNAVAILABLE" };
    }
    let key = Buffer.from(credential).toString("utf8");
    if (!/^sk_test_[A-Za-z0-9]+$/.test(key)) {
      key = "";
      return { ok: false, error: "CREDENTIAL_UNAVAILABLE" };
    }
    let response: unknown;
    try {
      response = await this.exchange(key, code);
    } catch {
      return { ok: false, error: "EXCHANGE_FAILED" };
    } finally {
      key = "";
    }
    const tokens = parseStripeOAuthTokens(response);
    if (!tokens) return { ok: false, error: "INVALID_RESPONSE" };
    if (tokens.livemode) return { ok: false, error: "LIVE_MODE" };
    if (tokens.accountId !== this.expectedAccountId) return { ok: false, error: "ACCOUNT_MISMATCH" };
    if (this.bind) {
      try {
        if (await this.bind(session, tokens)) return { ok: true, accountId: tokens.accountId, connected: true };
      } catch {
        // The callback reports only a sanitized failure code.
      }
      return { ok: false, error: "BINDING_FAILED" };
    }
    return { ok: true, accountId: tokens.accountId };
  }
}
