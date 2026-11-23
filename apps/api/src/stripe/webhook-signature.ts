import Stripe from "stripe";

export function validWebhookSecrets(secrets: readonly string[]): boolean {
  return secrets.length >= 1 && secrets.length <= 2 &&
    secrets.every((secret) => /^whsec_[A-Za-z0-9]+$/.test(secret)) &&
    new Set(secrets).size === secrets.length;
}

export function verifyWebhookSignature(payload: Buffer, signature: string, secrets: readonly string[]): Stripe.Event | null {
  if (!Buffer.isBuffer(payload) || payload.length === 0 || payload.length > 256 * 1024 ||
      !signature || signature.length > 4096) return null;
  // The SDK verifies decoded text; reject byte sequences that decode ambiguously.
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    if (!Buffer.from(decoded, "utf8").equals(payload)) return null;
  } catch (error) {
    if (error instanceof TypeError) return null;
    throw error;
  }
  for (const secret of secrets) {
    try {
      return Stripe.webhooks.constructEvent(payload, signature, secret);
    } catch (error) {
      if (error instanceof Stripe.errors.StripeSignatureVerificationError) continue;
      if (error instanceof SyntaxError) return null;
      throw error;
    }
  }
  return null;
}
