import { describe, expect, it, vi } from "vitest";
import type { CheckoutClaim } from "./checkout-store.js";
import { CheckoutService } from "./checkout-service.js";

const orderId = "c460d655-432f-4f4f-bb7c-ae34a4b5bc0b";
const attemptId = "24b22e4e-f0cc-49d5-873f-fb8fb26560cb";
const operationId = "b89df360-a806-4e8d-b187-f7d05e51770e";
const publicationId = "945d3694-4c80-423d-9284-d74a924c52e6";
const businessId = "148c5c6e-2081-4abd-80d2-cc31861978e1";
const origin = "https://first-shop.example";
const returnUrl = `${origin}/checkout/return?session_id={CHECKOUT_SESSION_ID}`;
const now = new Date();
const claim: CheckoutClaim = {
  order: { id: orderId, publicationId, storefrontRevision: null, storefrontRequestId: null,
    initialPaymentStatus: "UNPAID", paidQuantity: null, createdAt: now },
  attempt: {
    id: attemptId, orderId, status: "CREATING", operationId, claimedAt: now,
    stripeSessionId: null, createdAt: now, updatedAt: now
  },
  publication: {
    id: publicationId, draftId: "c2d4d506-6cb2-4c60-9825-e42dc6ced563", businessId,
    actorId: "e7d6428a-0a6a-4c88-bf59-267dc1b95d55", actorSessionVersion: 1,
    connectionId: "b461ae25-bd95-4df3-93f5-245783c3e756", mode: "TEST", stripeAccountId: "acct_123",
    name: "Service", description: "", kind: "SERVICE", amountCents: 5000, currency: "USD",
    billing: "ONE_TIME", interval: null, status: "PRICE_CREATED", operationId: null, claimedAt: null,
    stripeProductId: "prod_123", stripePriceId: "price_123", createdAt: now, updatedAt: now
  }
};
const price = {
  id: "price_123", object: "price", active: true, livemode: false, currency: "usd",
  unit_amount: 5000, type: "one_time", product: "prod_123", billing_scheme: "per_unit",
  custom_unit_amount: null, transform_quantity: null, recurring: null
};
const session = {
  id: "cs_test_123", object: "checkout.session", livemode: false, status: "open", mode: "payment",
  ui_mode: "embedded_page", currency: "usd", amount_subtotal: 5000, automatic_tax: { enabled: true },
  metadata: { kuzushi_order_id: orderId, kuzushi_attempt_id: attemptId }, client_secret: "cs_test_123_secret_abc"
};
function setup() {
  const store = {
    begin: vi.fn().mockResolvedValue({ orderId, attemptId }),
    claim: vi.fn().mockResolvedValueOnce(claim).mockResolvedValue(null),
    recordSession: vi.fn().mockResolvedValue(true)
  };
  const client = {
    accounts: { retrieveCurrent: vi.fn().mockResolvedValue({ object: "account", id: "acct_123" }) },
    prices: { retrieve: vi.fn().mockResolvedValue(price) },
    checkout: { sessions: { create: vi.fn().mockResolvedValue(session) } }
  };
  return { service: new CheckoutService(store, client, businessId, origin, returnUrl), store, client };
}

describe("durable checkout creation", () => {
  it("uses the application return URL for owner checkout without a storefront revision", async () => {
    const { store, client } = setup();
    const dashboard = {
      origin: "https://pay.example.com", revision: null, mode: "LIVE" as const, requestId: attemptId,
      connectionId: claim.publication.connectionId,
      dashboardReturnUrl: "https://pay.example.com/?session_id={CHECKOUT_SESSION_ID}"
    };
    const liveClaim = {
      ...claim, order: { ...claim.order, storefrontRequestId: dashboard.requestId },
      publication: { ...claim.publication, mode: "LIVE" },
      storefront: { origin: dashboard.origin, returnUrl: dashboard.dashboardReturnUrl }
    };
    store.claim.mockReset()
      .mockResolvedValueOnce({ ...liveClaim, storefront: { origin: dashboard.origin, returnUrl } })
      .mockResolvedValueOnce(liveClaim);
    const service = new CheckoutService(store, client, businessId, dashboard, undefined, {
      connectionId: dashboard.connectionId, accountId: claim.publication.stripeAccountId
    });
    await expect(service.begin(publicationId)).resolves.toEqual({ orderId, attemptId });
    expect(store.begin).toHaveBeenCalledWith(businessId, publicationId, dashboard);
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(client.checkout.sessions.create).not.toHaveBeenCalled();
    client.prices.retrieve.mockResolvedValueOnce({ ...price, livemode: true });
    client.checkout.sessions.create.mockResolvedValueOnce({ ...session, id: "cs_live_123", livemode: true,
      client_secret: "cs_live_123_secret_fixture" });
    await expect(service.create(attemptId)).resolves.toEqual({ clientSecret: "cs_live_123_secret_fixture" });
    expect(client.checkout.sessions.create).toHaveBeenCalledWith(
      expect.objectContaining({ return_url: dashboard.dashboardReturnUrl }), expect.anything()
    );
  });
  it("records a live OAuth session and refuses another merchant before dispatch", async () => {
    const { store, client } = setup();
    const storefront = { mode: "LIVE" as const, origin, revision: orderId,
      connectionId: claim.publication.connectionId, requestId: attemptId };
    const binding = { connectionId: storefront.connectionId, accountId: claim.publication.stripeAccountId };
    const liveClaim = { ...claim, storefront: { origin, returnUrl },
      order: { ...claim.order, storefrontRevision: storefront.revision, storefrontRequestId: storefront.requestId },
      publication: { ...claim.publication, mode: "LIVE" }
    };
    store.claim.mockReset().mockResolvedValueOnce({ ...liveClaim, publication: { ...liveClaim.publication, stripeAccountId: "acct_Other" } })
      .mockResolvedValueOnce(liveClaim);
    const service = new CheckoutService(store, client, businessId, storefront, undefined, binding);
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(client.checkout.sessions.create).not.toHaveBeenCalled();
    client.prices.retrieve.mockResolvedValueOnce({ ...price, livemode: true });
    client.checkout.sessions.create.mockResolvedValueOnce({ ...session, id: "cs_live_123", livemode: true,
      client_secret: "cs_live_123_secret_fixture" });
    await expect(service.create(attemptId)).resolves.toEqual({ clientSecret: "cs_live_123_secret_fixture" });
    expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
    expect(store.recordSession).toHaveBeenCalledExactlyOnceWith(attemptId, operationId, "cs_live_123");
  });

  it("uses the stored price and returns only the client secret after recording the session", async () => {
    const { service, store, client } = setup();
    await expect(service.begin(publicationId)).resolves.toEqual({ orderId, attemptId });
    expect(store.begin).toHaveBeenCalledWith(businessId, publicationId);
    await expect(service.create(attemptId)).resolves.toEqual({ clientSecret: session.client_secret });
    expect(store.claim).toHaveBeenCalledWith(businessId, attemptId);
    expect(store.recordSession).toHaveBeenCalledWith(attemptId, operationId, session.id);
    const [params, options] = client.checkout.sessions.create.mock.calls[0];
    expect(params.line_items[0]).toEqual({
      price: "price_123", quantity: 1, adjustable_quantity: { enabled: true, minimum: 1, maximum: 50 }
    });
    expect(params.return_url).toBe(returnUrl);
    expect(options.idempotencyKey).toBe(`kp-checkout-${attemptId}`);
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(client.checkout.sessions.create).toHaveBeenCalledOnce();
  });

  it("does not return a secret when the session outcome cannot be persisted", async () => {
    const { service, store, client } = setup();
    store.recordSession.mockRejectedValueOnce(new Error("database details"));
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(client.checkout.sessions.create).toHaveBeenCalledOnce();
  });

  it("does not dispatch for invalid snapshots or mismatched Stripe prices", async () => {
    const first = setup();
    first.store.claim.mockReset().mockResolvedValueOnce({
      ...claim, publication: { ...claim.publication, amountCents: -1 }
    });
    await expect(first.service.create(attemptId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(first.client.checkout.sessions.create).not.toHaveBeenCalled();
    const second = setup();
    second.client.prices.retrieve.mockResolvedValueOnce({ ...price, livemode: true });
    await expect(second.service.create(attemptId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(second.client.checkout.sessions.create).not.toHaveBeenCalled();
  });

  it("treats a failed Stripe creation as uncertain and does not retry", async () => {
    const { service, client } = setup();
    client.checkout.sessions.create.mockRejectedValueOnce(new Error("provider details"));
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
    await expect(service.create(attemptId)).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(client.checkout.sessions.create).toHaveBeenCalledOnce();
  });

  it("rejects unsafe configuration and invalid identifiers before claiming", async () => {
    const { store, client, service } = setup();
    expect(() => new CheckoutService(store, client, businessId, origin, "https://other.example/return"))
      .toThrow("Invalid embedded checkout configuration");
    expect(() => new CheckoutService(store, client, "invalid", origin, returnUrl))
      .toThrow("Invalid embedded checkout configuration");
    await expect(service.create("invalid")).rejects.toMatchObject({ code: "UNAVAILABLE" });
    await expect(service.begin("invalid")).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(store.claim).not.toHaveBeenCalled();
    expect(store.begin).not.toHaveBeenCalled();
  });

  it("uses each business's own storefront and refuses another business's checkout", async () => {
    const first = setup();
    const second = setup();
    const otherBusinessId = "fe69099f-8aa1-4c1e-a3fc-a47f378cd7d0";
    const otherOrigin = "https://second-shop.example";
    const otherReturnUrl = `${otherOrigin}/confirmation?session_id={CHECKOUT_SESSION_ID}`;
    second.store.claim.mockReset().mockResolvedValueOnce({
      ...claim, publication: { ...claim.publication, businessId: otherBusinessId }
    });
    const otherService = new CheckoutService(second.store, second.client, otherBusinessId, otherOrigin, otherReturnUrl);
    await first.service.create(attemptId);
    await otherService.create(attemptId);
    expect(first.client.checkout.sessions.create.mock.calls[0][0].return_url).toBe(returnUrl);
    expect(second.client.checkout.sessions.create.mock.calls[0][0].return_url).toBe(otherReturnUrl);
    expect(second.store.claim).toHaveBeenCalledWith(otherBusinessId, attemptId);

    const wrongBusiness = setup();
    const wronglyBound = new CheckoutService(wrongBusiness.store, wrongBusiness.client, otherBusinessId, otherOrigin, otherReturnUrl);
    await expect(wronglyBound.create(attemptId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(wrongBusiness.client.checkout.sessions.create).not.toHaveBeenCalled();
  });
});
