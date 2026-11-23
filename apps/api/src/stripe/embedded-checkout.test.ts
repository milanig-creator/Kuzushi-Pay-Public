import { createServer } from "node:http";
import Stripe from "stripe";
import { describe, expect, it, vi } from "vitest";
import { EmbeddedCheckout, EmbeddedCheckoutError, type EmbeddedCheckoutInput } from "./embedded-checkout.js";
import { hasStorefrontDnsProof, parseStorefrontProposal } from "./storefront-proposal.js";

const orderId = "fe3f7f40-b096-4d86-b0e6-17b5dc53faaa";
const attemptId = "6254656f-f672-4df4-a6ce-a493b5892c55";
const origin = "https://shop.example.com";
const returnUrl = `${origin}/checkout/return?session_id={CHECKOUT_SESSION_ID}`;
const input: EmbeddedCheckoutInput = {
  orderId, attemptId, productId: "prod_123", priceId: "price_123", amountCents: 5000,
  billing: "ONE_TIME", interval: null
};
const account = { id: "acct_123", object: "account" };
const price = {
  id: input.priceId, object: "price", active: true, livemode: false, currency: "usd",
  unit_amount: input.amountCents, type: "one_time", product: input.productId,
  billing_scheme: "per_unit", custom_unit_amount: null, transform_quantity: null, recurring: null
};
const session = {
  id: "cs_test_123", object: "checkout.session", livemode: false, status: "open",
  mode: "payment", ui_mode: "embedded_page", currency: "usd", amount_subtotal: 5000,
  client_secret: "cs_test_123_secret_abc", automatic_tax: { enabled: true },
  metadata: { kuzushi_order_id: orderId, kuzushi_attempt_id: attemptId }
};

function setup() {
  const client = {
    accounts: { retrieveCurrent: vi.fn().mockResolvedValue(account) },
    prices: { retrieve: vi.fn().mockResolvedValue(price) },
    checkout: { sessions: { create: vi.fn().mockResolvedValue(session) } }
  };
  return { client, checkout: new EmbeddedCheckout(client, account.id, "TEST", origin, returnUrl) };
}

describe("storefront proposals", () => {
  it("accepts only a bounded HTTPS origin and same-origin checkout return URL", () => {
    expect(parseStorefrontProposal({ origin, returnUrl })).toEqual({ origin, returnUrl });
    for (const candidate of [
      { origin: "http://shop.example.com", returnUrl },
      { origin: `${origin}/path`, returnUrl },
      { origin, returnUrl: "https://other.example/return?session_id={CHECKOUT_SESSION_ID}" },
      { origin, returnUrl: `${origin}/return?session_id={CHECKOUT_SESSION_ID}&other=x` },
      { origin, returnUrl: `${origin}/return?session_id={CHECKOUT_SESSION_ID}#fragment` },
      { origin, returnUrl: `${origin}/return \n?session_id={CHECKOUT_SESSION_ID}` },
      { origin, returnUrl: `${origin}/${"x".repeat(2048)}?session_id={CHECKOUT_SESSION_ID}` },
      { origin, returnUrl, verified: true }
    ]) expect(() => parseStorefrontProposal(candidate)).toThrow("Invalid storefront proposal");
  });

  it("requires the current revision in one DNS record and handles resolver failures", async () => {
    const revision = "c8551e23-7881-4ec2-95c3-de284670ae3d";
    const proposal = {
      businessId: "business-a", origin, returnUrl, revision,
      createdAt: new Date(), updatedAt: new Date(), verifiedAt: null, testApprovedAt: null
    };
    const resolveTxt = vi.fn<(name: string) => Promise<string[][]>>()
      .mockResolvedValueOnce([["kuzushi-pay-verification="], [revision]])
      .mockResolvedValueOnce([["other-value"], ["kuzushi-pay-verification=", revision]])
      .mockRejectedValueOnce(new Error("DNS unavailable"));
    await expect(hasStorefrontDnsProof(proposal, resolveTxt)).resolves.toBe(false);
    await expect(hasStorefrontDnsProof(proposal, resolveTxt)).resolves.toBe(true);
    await expect(hasStorefrontDnsProof(proposal, resolveTxt)).resolves.toBe(false);
    await expect(hasStorefrontDnsProof({ ...proposal, origin: "https://127.0.0.1" }, resolveTxt)).resolves.toBe(false);
    expect(resolveTxt).toHaveBeenCalledTimes(3);
    expect(resolveTxt).toHaveBeenLastCalledWith("_kuzushi-pay.shop.example.com.");
  });
});

describe("embedded checkout gateway", () => {
  it("creates a one-time session with a fixed return URL, Stripe Tax and quantity 1–50", async () => {
    const { checkout, client } = setup();
    await expect(checkout.create(input)).resolves.toEqual({
      sessionId: session.id, clientSecret: session.client_secret
    });
    expect(client.checkout.sessions.create).toHaveBeenCalledWith({
      ui_mode: "embedded_page", mode: "payment",
      line_items: [{ price: input.priceId, quantity: 1, adjustable_quantity: { enabled: true, minimum: 1, maximum: 50 } }],
      automatic_tax: { enabled: true }, adaptive_pricing: { enabled: false }, return_url: returnUrl,
      metadata: { kuzushi_order_id: orderId, kuzushi_attempt_id: attemptId }
    }, { idempotencyKey: `kp-checkout-${attemptId}` });
  });

  it("validates recurring pricing and creates subscription sessions", async () => {
    const { checkout, client } = setup();
    client.prices.retrieve.mockResolvedValue({
      ...price, type: "recurring",
      recurring: { interval: "month", interval_count: 1, usage_type: "licensed", trial_period_days: null }
    });

    client.checkout.sessions.create.mockResolvedValue({ ...session, mode: "subscription" });
    await expect(checkout.create({ ...input, billing: "RECURRING", interval: "MONTH" }))
      .resolves.toHaveProperty("clientSecret", session.client_secret);
    expect(client.checkout.sessions.create.mock.calls[0][0].mode).toBe("subscription");
  });

  it("uses the same attempt idempotency key and parameters on retry", async () => {
    const { checkout, client } = setup();
    await checkout.create(input);
    await checkout.create(input);
    expect(client.checkout.sessions.create.mock.calls[0]).toEqual(client.checkout.sessions.create.mock.calls[1]);
  });

  it("uses the validated snapshot even if the caller changes its input during preparation", async () => {
    const { checkout, client } = setup();
    const mutable = { ...input };
    client.accounts.retrieveCurrent.mockImplementationOnce(async () => {
      mutable.priceId = "price_other";
      mutable.attemptId = "cf3c9515-269b-4915-a085-fb388d5617dd";
      return account;
    });
    await checkout.create(mutable);
    expect(client.prices.retrieve).toHaveBeenCalledWith(input.priceId);
    expect(client.checkout.sessions.create.mock.calls[0][1].idempotencyKey).toBe(`kp-checkout-${attemptId}`);
  });

  it("accepts live objects only when the gateway is configured for live mode", async () => {
    const { client } = setup();
    client.prices.retrieve.mockResolvedValue({ ...price, livemode: true });
    client.checkout.sessions.create.mockResolvedValue({
      ...session, id: "cs_live_123", livemode: true, client_secret: "cs_live_123_secret_abc"
    });
    const checkout = new EmbeddedCheckout(client, account.id, "LIVE", origin, returnUrl);
    await expect(checkout.create(input)).resolves.toHaveProperty("sessionId", "cs_live_123");
    client.prices.retrieve.mockResolvedValue(price);
    await expect(checkout.create(input)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(client.checkout.sessions.create).toHaveBeenCalledOnce();
  });

  it("rejects untrusted or inconsistent input before calling Stripe", async () => {
    const { checkout, client } = setup();
    for (const candidate of [
      { ...input, orderId: "bad" }, { ...input, attemptId: "bad" }, { ...input, amountCents: 0 },
      { ...input, priceId: "bad" }, { ...input, billing: "RECURRING", interval: null },
      { ...input, billing: "ONE_TIME", interval: "MONTH" }, { ...input, returnUrl: "https://evil.example" }
    ]) {
      await expect(checkout.create(candidate as EmbeddedCheckoutInput)).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
  });

  it("rejects a mismatched account or price, including changed billing semantics", async () => {
    const badPrices = [
      { id: "price_other" }, { active: false }, { livemode: true }, { currency: "eur" },
      { unit_amount: 1 }, { product: "prod_other" }, { billing_scheme: "tiered" },
      { transform_quantity: {} }, { custom_unit_amount: {} },
      { type: "recurring", recurring: { interval: "month", interval_count: 2, usage_type: "licensed", trial_period_days: null } },
      { type: "recurring", recurring: { interval: "month", interval_count: 1, usage_type: "metered", trial_period_days: null } },
      { type: "recurring", recurring: { interval: "month", interval_count: 1, usage_type: "licensed", trial_period_days: 7 } }
    ];
    for (const badPrice of badPrices) {
      const { checkout, client } = setup();
      client.prices.retrieve.mockResolvedValue({ ...price, ...badPrice });
      const recurring = badPrice.type === "recurring";
      await expect(checkout.create(recurring ? { ...input, billing: "RECURRING", interval: "MONTH" } : input))
        .rejects.toMatchObject({ code: "PREPARATION_FAILED" });
      expect(client.checkout.sessions.create).not.toHaveBeenCalled();
    }
    const { checkout, client } = setup();
    client.accounts.retrieveCurrent.mockResolvedValue({ ...account, id: "acct_other" });
    await expect(checkout.create(input)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(client.checkout.sessions.create).not.toHaveBeenCalled();
  });

  it("treats create failures and unexpected session responses as uncertain, without leaking provider errors", async () => {
    const { checkout, client } = setup();
    client.checkout.sessions.create.mockRejectedValueOnce(new Error("sensitive provider message"));
    await expect(checkout.create(input)).rejects.toEqual(new EmbeddedCheckoutError("OUTCOME_UNCERTAIN"));
    for (const badSession of [
      { livemode: true }, { status: "complete" }, { mode: "subscription" },
      { amount_subtotal: 4999 }, { automatic_tax: { enabled: false } },
      { metadata: { kuzushi_order_id: orderId, kuzushi_attempt_id: "other" } },
      { client_secret: null }, { id: null }
    ]) {
      client.checkout.sessions.create.mockResolvedValueOnce({ ...session, ...badSession });
      await expect(checkout.create(input)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
    }
  });

  it("reports pre-dispatch failures without exposing provider messages", async () => {
    const { checkout, client } = setup();
    client.prices.retrieve.mockRejectedValueOnce(new Error("sensitive provider message"));
    await expect(checkout.create(input)).rejects.toEqual(new EmbeddedCheckoutError("PREPARATION_FAILED"));
    expect(client.checkout.sessions.create).not.toHaveBeenCalled();
  });

  it("rejects unsafe return URL configuration", () => {
    const { client } = setup();
    for (const url of [
      `http://shop.example.com/return?session_id={CHECKOUT_SESSION_ID}`,
      `https://evil.example/return?session_id={CHECKOUT_SESSION_ID}`,
      `${origin}/return?session_id={CHECKOUT_SESSION_ID}&next=other`,
      `${origin}/return?session_id={CHECKOUT_SESSION_ID}#fragment`,
      `${origin}/return?session_id=other`, "not-a-url"
    ]) {
      expect(() => new EmbeddedCheckout(client, account.id, "TEST", origin, url)).toThrow("Invalid embedded checkout configuration");
    }
  });

  it("uses the pinned SDK against loopback with the expected request and idempotency key", async () => {
    const requests: { method: string | undefined; url: string | undefined; body: string; key: string | string[] | undefined }[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        requests.push({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString(), key: req.headers["idempotency-key"] });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(req.url === "/v1/account" ? account : req.url === "/v1/prices/price_123" ? price : session));
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing test server address");
      const stripe = new Stripe("rk_test_placeholder", {
        host: "127.0.0.1", port: address.port, protocol: "http",
        apiVersion: "2026-10-28.endive", maxNetworkRetries: 0
      });
      const checkout = new EmbeddedCheckout(stripe, account.id, "TEST", origin, returnUrl);
      await expect(checkout.create(input)).resolves.toHaveProperty("sessionId", session.id);
      expect(requests.map(({ method, url }) => [method, url])).toEqual([
        ["GET", "/v1/account"], ["GET", "/v1/prices/price_123"], ["POST", "/v1/checkout/sessions"]
      ]);
      const body = new URLSearchParams(requests[2].body);
      expect(body.get("ui_mode")).toBe("embedded_page");
      expect(body.get("line_items[0][adjustable_quantity][minimum]")).toBe("1");
      expect(body.get("line_items[0][adjustable_quantity][maximum]")).toBe("50");
      expect(body.get("automatic_tax[enabled]")).toBe("true");
      expect(body.get("adaptive_pricing[enabled]")).toBe("false");
      expect(body.get("return_url")).toBe(returnUrl);
      expect(requests[2].key).toBe(`kp-checkout-${attemptId}`);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
