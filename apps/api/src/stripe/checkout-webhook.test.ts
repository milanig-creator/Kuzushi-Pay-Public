import Stripe from "stripe";
import { describe, expect, it, vi } from "vitest";
import { CheckoutWebhookInbox, CheckoutWebhookReceiver, type CheckoutWebhookBinding } from "./checkout-webhook.js";

const secret = "whsec_fixtureSecret";
const oldSecret = "whsec_oldFixture";
const binding: CheckoutWebhookBinding = {
  connectionId: "1188d7bf-c6d3-4fdb-ae3d-cf7222fe61f6",
  businessId: "d049d2ed-8223-4abd-95e3-a0a85ca8e6e9",
  accountId: "acct_123", mode: "LIVE", source: "direct"
};
const event = {
  id: "evt_123", object: "event", type: "checkout.session.completed",
  created: 1_700_000_000, livemode: true,
  data: { object: { id: "cs_live_123", object: "checkout.session", customer_email: "private@example.com" } }
};
function signed(payload: string, key = secret, timestamp = Math.floor(Date.now() / 1000)) {
  return Stripe.webhooks.generateTestHeaderString({ payload, secret: key, timestamp });
}
function setup(config = binding) {
  const store = { record: vi.fn().mockResolvedValue("inserted") };
  return { inbox: new CheckoutWebhookInbox(config, [secret, oldSecret], store), store };
}

describe("checkout webhook inbox", () => {
  it("resolves only the requested connection and fails closed on a conflicting binding", async () => {
    const store = { record: vi.fn().mockResolvedValue("inserted") };
    const bindings = { resolve: vi.fn().mockResolvedValue(null) };
    const receiver = new CheckoutWebhookReceiver(bindings, store);
    const payload = JSON.stringify(event);
    await expect(receiver.accept("bad", Buffer.from(payload), signed(payload))).resolves.toBe("invalid");
    await expect(receiver.accept(binding.connectionId, Buffer.from(payload), "")).resolves.toBe("invalid");
    expect(bindings.resolve).not.toHaveBeenCalled();
    await expect(receiver.accept(binding.connectionId, Buffer.from(payload), signed(payload))).resolves.toBe("unavailable");
    bindings.resolve.mockResolvedValueOnce({
      binding: { ...binding, connectionId: "530d5894-4c02-43dc-afaf-d5df45c1866b" }, secrets: [secret]
    });
    await expect(receiver.accept(binding.connectionId, Buffer.from(payload), signed(payload)))
      .rejects.toThrow("Checkout webhook binding mismatch");
    expect(store.record).not.toHaveBeenCalled();
  });

  it("verifies live direct events and passes only minimal metadata to durable storage", async () => {
    const { inbox, store } = setup();
    const payload = JSON.stringify(event);
    await expect(inbox.accept(Buffer.from(payload), signed(payload, oldSecret))).resolves.toBe("inserted");
    expect(store.record).toHaveBeenCalledWith(binding, {
      id: event.id, type: event.type, sessionId: "cs_live_123", created: event.created
    });
  });

  it("rejects signatures, account and mode mismatches before persistence", async () => {
    const { inbox, store } = setup();
    const payload = JSON.stringify(event);
    await expect(inbox.accept(Buffer.from(payload), signed(payload, "whsec_wrong"))).resolves.toBe("invalid");
    await expect(inbox.accept(Buffer.from(payload), signed(payload, secret, Math.floor(Date.now() / 1000) - 301)))
      .resolves.toBe("invalid");
    await expect(inbox.accept(Buffer.from(payload + " "), signed(payload))).resolves.toBe("invalid");
    await expect(inbox.accept(Buffer.alloc(256 * 1024 + 1), signed(payload))).resolves.toBe("invalid");
    for (const bad of [
      { ...event, livemode: false }, { ...event, account: "acct_other" },
      { ...event, data: { object: { id: "cs_test_123", object: "checkout.session" } } },
      { ...event, data: { object: { id: "cs_live_123", object: "invoice" } } }
    ]) {
      const body = JSON.stringify(bad);
      await expect(inbox.accept(Buffer.from(body), signed(body))).resolves.toBe("invalid");
    }
    expect(store.record).not.toHaveBeenCalled();
  });

  it("requires the connected account and ignores other verified event types", async () => {
    const { inbox, store } = setup({ ...binding, mode: "TEST", source: "connected" });
    const withoutAccount = JSON.stringify({
      ...event, livemode: false, data: { object: { id: "cs_test_123", object: "checkout.session" } }
    });
    await expect(inbox.accept(Buffer.from(withoutAccount), signed(withoutAccount))).resolves.toBe("invalid");
    const connected = JSON.stringify({
      ...event, account: "acct_123", livemode: false, data: { object: { id: "cs_test_123", object: "checkout.session" } }
    });
    await expect(inbox.accept(Buffer.from(connected), signed(connected))).resolves.toBe("inserted");
    const unsupported = JSON.stringify({
      ...event, account: "acct_123", livemode: false, type: "invoice.paid", data: { object: { id: "in_123" } }
    });
    await expect(inbox.accept(Buffer.from(unsupported), signed(unsupported))).resolves.toBe("ignored");
    expect(store.record).toHaveBeenCalledOnce();
  });

  it("rejects malformed or ambiguous bytes and surfaces storage failures", async () => {
    const { inbox, store } = setup();
    const payload = JSON.stringify(event);
    const malformed = "{";
    await expect(inbox.accept(Buffer.from(malformed), signed(malformed))).resolves.toBe("invalid");
    const invalidUtf8 = Buffer.concat([Buffer.from(payload.slice(0, -1)), Buffer.from([0xff, 0x7d])]);
    await expect(inbox.accept(invalidUtf8, signed(payload))).resolves.toBe("invalid");
    store.record.mockRejectedValueOnce(new Error("storage unavailable"));
    await expect(inbox.accept(Buffer.from(payload), signed(payload))).rejects.toThrow("storage unavailable");
  });

  it("rejects untrusted bindings and duplicate signing secrets", () => {
    const store = { record: vi.fn() };
    expect(() => new CheckoutWebhookInbox({ ...binding, businessId: "bad" }, [secret], store)).toThrow();
    expect(() => new CheckoutWebhookInbox(binding, [secret, secret], store)).toThrow();
  });
});
