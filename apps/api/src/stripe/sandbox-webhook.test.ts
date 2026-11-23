import Stripe from "stripe";
import { describe, expect, it } from "vitest";
import { SandboxWebhookVerifier } from "./sandbox-webhook.js";

const secret = "whsec_sandboxTestSecret";
const oldSecret = "whsec_previousTestSecret";
const endpoint = { accountId: "acct_expected", source: "connected" } as const;
const event = {
  id: "evt_test123", object: "event", type: "checkout.session.completed",
  created: 1_700_000_000, livemode: false, account: "acct_expected",
  data: { object: { id: "cs_test_123", customer_email: "private@example.com" } }
};

function signed(payload: string, key = secret, timestamp = Math.floor(Date.now() / 1000)) {
  return Stripe.webhooks.generateTestHeaderString({ payload, secret: key, timestamp });
}

describe("sandbox Stripe webhook verification", () => {
  it("verifies raw bytes and returns only safe metadata", () => {
    const payload = JSON.stringify(event);
    const verifier = new SandboxWebhookVerifier(endpoint, [secret]);
    expect(verifier.verify(Buffer.from(payload), signed(payload))).toEqual({
      id: event.id, type: event.type, created: event.created, accountId: endpoint.accountId, source: "connected"
    });
    expect(verifier.verify(Buffer.from(payload + " "), signed(payload))).toBeNull();
    expect(verifier.verify(Buffer.from(payload), signed(payload, "whsec_wrongSecret"))).toBeNull();
    expect(verifier.verify(Buffer.from(payload), signed(payload, secret, Math.floor(Date.now() / 1000) - 301))).toBeNull();
    expect(verifier.verify(Buffer.from(payload), "")).toBeNull();
    expect(verifier.verify(Buffer.alloc(256 * 1024 + 1), signed(payload))).toBeNull();
    const unicode = JSON.stringify({ ...event, data: { object: { value: "\ufffd" } } });
    const index = unicode.indexOf("\ufffd");
    const invalidUtf8 = Buffer.concat([Buffer.from(unicode.slice(0, index)), Buffer.from([0xff]), Buffer.from(unicode.slice(index + 1))]);
    expect(verifier.verify(invalidUtf8, signed(unicode))).toBeNull();
    expect(verifier.verify(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(payload)]), signed(payload))).toBeNull();
  });

  it("accepts an old signing secret during rotation without accepting another account or live events", () => {
    const verifier = new SandboxWebhookVerifier(endpoint, [secret, oldSecret]);
    const payload = JSON.stringify(event);
    expect(verifier.verify(Buffer.from(payload), signed(payload, oldSecret))).not.toBeNull();
    for (const bad of [
      { ...event, livemode: true },
      { ...event, account: "acct_other" },
      { ...event, account: undefined },
      { ...event, id: "not-an-event" },
      { ...event, data: {} }
    ]) {
      const body = JSON.stringify(bad);
      expect(verifier.verify(Buffer.from(body), signed(body))).toBeNull();
    }
  });

  it("associates direct-account events only with the preconfigured destination", () => {
    const verifier = new SandboxWebhookVerifier({ accountId: "acct_expected", source: "direct" }, [secret]);
    const payload = JSON.stringify({ ...event, account: undefined });
    expect(verifier.verify(Buffer.from(payload), signed(payload))).toMatchObject({
      accountId: "acct_expected", source: "direct"
    });
    const wrongAccount = JSON.stringify({ ...event, account: "acct_other" });
    expect(verifier.verify(Buffer.from(wrongAccount), signed(wrongAccount))).toBeNull();
    const malformed = "{";
    expect(verifier.verify(Buffer.from(malformed), signed(malformed))).toBeNull();
  });

  it("rejects unsafe configuration and does not treat thin events as verified snapshots", () => {
    expect(() => new SandboxWebhookVerifier(endpoint, [])).toThrow();
    expect(() => new SandboxWebhookVerifier(endpoint, [secret, secret])).toThrow();
    expect(() => new SandboxWebhookVerifier(endpoint, ["not-a-signing-secret"])).toThrow();
    expect(() => new SandboxWebhookVerifier({ ...endpoint, accountId: "other" }, [secret])).toThrow();
    const thin = JSON.stringify({ ...event, object: "v2.core.event" });
    expect(() => new SandboxWebhookVerifier(endpoint, [secret]).verify(Buffer.from(thin), signed(thin))).toThrow();
  });
});
