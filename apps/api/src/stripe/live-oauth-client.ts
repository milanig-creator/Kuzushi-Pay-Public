import { createHash } from "node:crypto";
import Stripe from "stripe";
import type { SecretManager, SecretVersion } from "../secrets/secret-manager.js";
import { parseStripeOAuthTokens } from "./oauth-sandbox-exchange.js";
import type { OAuthTokenRotation } from "./oauth-token-rotation.js";

type Binding = { connectionId: string; accountId: string; reference: SecretVersion };
const usableForMs = 50 * 60 * 1000;

export async function loadLiveOAuthClient(
  businessId: string, expectedAccountId: string,
  find: (businessId: string) => Promise<Binding | null>,
  secrets: Pick<SecretManager, "accessVersion">, rotation: Pick<OAuthTokenRotation, "rotate">
) {
  const secretId = `kp-stripe-oauth-live-${createHash("sha256").update(businessId).digest("hex").slice(0, 32)}`;
  const binding = await find(businessId);
  if (!binding || binding.accountId !== expectedAccountId || binding.reference.secretId !== secretId ||
      !/^[1-9][0-9]*$/.test(binding.reference.version)) throw new Error("Live Stripe OAuth binding unavailable");

  const read = async (reference: SecretVersion) => {
    const payload: unknown = JSON.parse(Buffer.from(await secrets.accessVersion(reference)).toString("utf8"));
    const tokens = parseStripeOAuthTokens(payload);
    if (!tokens?.livemode || tokens.accountId !== binding.accountId) throw new Error("Live Stripe OAuth binding mismatch");
    const issuedAt = payload && typeof payload === "object" && "issued_at" in payload ? payload.issued_at : undefined;
    const age = typeof issuedAt === "number" ? Date.now() - issuedAt : Infinity;
    return { token: tokens.accessToken, publishableKey: tokens.publishableKey, fresh: age >= 0 && age < usableForMs };
  };

  let reference = binding.reference;
  let credential = await read(reference);
  if (!credential.fresh) {
    await rotation.rotate(businessId, "LIVE", reference);
    const rotated = await find(businessId);
    if (!rotated || rotated.connectionId !== binding.connectionId || rotated.accountId !== binding.accountId ||
        rotated.reference.secretId !== secretId || rotated.reference.version === reference.version ||
        !/^[1-9][0-9]*$/.test(rotated.reference.version)) throw new Error("Live Stripe OAuth rotation unavailable");
    reference = rotated.reference;
    credential = await read(reference);
  }

  const current = await find(businessId);
  if (!credential.fresh || !current || current.connectionId !== binding.connectionId || current.accountId !== binding.accountId ||
      current.reference.secretId !== secretId || current.reference.version !== reference.version) {
    throw new Error("Live Stripe OAuth credential changed");
  }
  const client = new Stripe(credential.token, { timeout: 10_000, maxNetworkRetries: 0 });
  return { client, connectionId: current.connectionId, accountId: current.accountId, publishableKey: credential.publishableKey };
}
