import { randomBytes } from "node:crypto";
import type { SecretManager, SecretVersion } from "../secrets/secret-manager.js";
import { encodeStripeOAuthTokens, parseStripeOAuthTokens, refreshWithStripe, type StripeOAuthTokens } from "./oauth-sandbox-exchange.js";

type Mode = "TEST" | "LIVE";

export type RotationClaim = {
  connectionId: string;
  businessId: string;
  mode: Mode;
  accountId: string;
  operationId: string;
  reference: SecretVersion;
};

export interface OAuthRotationStore {
  claim(businessId: string, mode: Mode, operationId: string, expected?: SecretVersion): Promise<RotationClaim | null>;
  release(claim: RotationClaim): Promise<boolean>;
  complete(claim: RotationClaim, version: string): Promise<boolean>;
  requireReconnect(claim: RotationClaim): Promise<boolean>;
}

export class OAuthRotationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthRotationError";
  }
}

function matchesClaim(tokens: StripeOAuthTokens | null, claim: RotationClaim): tokens is StripeOAuthTokens {
  return !!tokens && tokens.accountId === claim.accountId && tokens.livemode === (claim.mode === "LIVE");
}

export class OAuthTokenRotation {
  constructor(
    private readonly store: OAuthRotationStore,
    private readonly secrets: Pick<SecretManager, "accessVersion" | "addVersion">,
    private readonly readDeveloperKey: (mode: Mode) => Promise<Uint8Array>,
    private readonly refresh: (key: string, token: string) => Promise<unknown> = refreshWithStripe
  ) {}

  async rotate(businessId: string, mode: Mode, expected?: SecretVersion): Promise<string> {
    const operationId = randomBytes(16).toString("hex");
    const claim = await this.store.claim(businessId, mode, operationId, expected);
    if (!claim) throw new OAuthRotationError("OAuth connection unavailable or refresh already in progress");

    let tokens: StripeOAuthTokens;
    let key: string;
    try {
      if (claim.businessId !== businessId || claim.mode !== mode || claim.operationId !== operationId ||
          (expected && (claim.reference.secretId !== expected.secretId || claim.reference.version !== expected.version)) ||
          !new RegExp(`^kp-stripe-oauth-${mode.toLowerCase()}-[0-9a-f]{32}$`).test(claim.reference.secretId) ||
          !/^[1-9][0-9]*$/.test(claim.reference.version) || !/^acct_[A-Za-z0-9]+$/.test(claim.accountId)) {
        throw new Error("Invalid claim");
      }
      const payload = await this.secrets.accessVersion(claim.reference);
      const parsed = parseStripeOAuthTokens(JSON.parse(Buffer.from(payload).toString("utf8")) as unknown);
      if (!matchesClaim(parsed, claim)) throw new Error("Invalid stored tokens");
      tokens = parsed;
      key = Buffer.from(await this.readDeveloperKey(mode)).toString("utf8");
      const expectedPrefix = mode === "TEST" ? "sk_test_" : "sk_live_";
      if (!key.startsWith(expectedPrefix) || !/^sk_(test|live)_[A-Za-z0-9]+$/.test(key)) {
        throw new Error("Invalid developer credential");
      }
    } catch {
      let released: boolean;
      try {
        released = await this.store.release(claim);
      } catch {
        throw new OAuthRotationError("OAuth refresh preparation failed; connection remains unavailable");
      }
      if (!released) throw new OAuthRotationError("OAuth refresh preparation failed; connection remains unavailable");
      throw new OAuthRotationError("OAuth refresh preparation failed");
    }

    try {
      const issuedAt = Date.now();
      const refreshed = parseStripeOAuthTokens(await this.refresh(key, tokens.refreshToken));
      if (!matchesClaim(refreshed, claim) || refreshed.refreshToken === tokens.refreshToken) {
        throw new Error("Invalid refreshed tokens");
      }
      refreshed.publishableKey ??= tokens.publishableKey;
      const reference = await this.secrets.addVersion(claim.reference.secretId,
        encodeStripeOAuthTokens(refreshed, mode === "LIVE" ? issuedAt : undefined));
      if (reference.secretId !== claim.reference.secretId || !/^[1-9][0-9]*$/.test(reference.version) ||
          reference.version === claim.reference.version) {
        throw new Error("Invalid secret version");
      }
      if (!await this.store.complete(claim, reference.version)) throw new Error("Connection changed");
      return refreshed.accessToken;
    } catch {
      try {
        await this.store.requireReconnect(claim);
      } catch {
        throw new OAuthRotationError("OAuth refresh outcome uncertain; connection remains unavailable");
      }
      throw new OAuthRotationError("OAuth refresh outcome uncertain; reconnect may be required");
    } finally {
      key = "";
    }
  }
}
