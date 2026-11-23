import { createServer } from "node:http";
import Stripe from "stripe";
import { describe, expect, it, vi } from "vitest";
import type { StripePublication } from "../generated/prisma/client.js";
import type { User } from "../repository.js";
import { ProductPublisher } from "./publish-product.js";

const actor: User = {
  id: "064797d8-6917-4134-a143-156624963321", email: "owner@example.com",
  passwordHash: "fixture", role: "USER", sessionVersion: 1
};
const businessId = "153205c0-819b-44b5-8e98-f734cb4f68e9";
const publicationId = "a61cd388-f071-4460-9c26-3dc2e93130cb";
const operationId = "fa709bde-0bc4-4d3e-979d-56dbb16e5469";
const initial: StripePublication = {
  id: publicationId, draftId: "4460c42c-421d-4c33-9881-fd3c4a4b6217", businessId,
  actorId: actor.id, actorSessionVersion: actor.sessionVersion, connectionId: "88cde83b-a8c0-491b-94b6-e0638ba16379",
  mode: "LIVE", stripeAccountId: "acct_123", name: "Service", description: "Description",
  kind: "SERVICE", amountCents: 5000, currency: "USD", billing: "ONE_TIME", interval: null,
  status: "PENDING", operationId: null, claimedAt: null, stripeProductId: null, stripePriceId: null,
  createdAt: new Date(), updatedAt: new Date()
};
const product = {
  id: "prod_123", object: "product", livemode: true, active: true,
  name: "Service", description: "Description",
  metadata: { kuzushi_publication_id: publicationId, kuzushi_kind: "SERVICE" }
};
const price = {
  id: "price_123", object: "price", active: true, livemode: true, currency: "usd",
  unit_amount: 5000, type: "one_time", product: product.id, billing_scheme: "per_unit",
  custom_unit_amount: null, transform_quantity: null, recurring: null,
  metadata: { kuzushi_publication_id: publicationId }
};

function setup(start: StripePublication = initial) {
  let row: StripePublication = { ...start };
  const store = {
    begin: vi.fn(async () => ({ ...row })),
    find: vi.fn(async () => ({ ...row })),
    claimProduct: vi.fn(async () => {
      if (row.status !== "PENDING") return null;
      row = { ...row, status: "PRODUCT_CREATING", operationId, claimedAt: new Date() };
      return { ...row };
    }),
    recordProduct: vi.fn(async (_id: string, operation: string, stripeProductId: string) => {
      if (row.status !== "PRODUCT_CREATING" || row.operationId !== operation) return false;
      row = { ...row, status: "PRODUCT_CREATED", operationId: null, claimedAt: null, stripeProductId };
      return true;
    }),
    claimPrice: vi.fn(async () => {
      if (row.status !== "PRODUCT_CREATED") return null;
      row = { ...row, status: "PRICE_CREATING", operationId, claimedAt: new Date() };
      return { ...row };
    }),
    recordPrice: vi.fn(async (_id: string, operation: string, stripePriceId: string) => {
      if (row.status !== "PRICE_CREATING" || row.operationId !== operation) return false;
      row = { ...row, status: "PRICE_CREATED", operationId: null, claimedAt: null, stripePriceId };
      return true;
    })
  };
  const client = {
    accounts: { retrieveCurrent: vi.fn().mockResolvedValue({ object: "account", id: "acct_123" }) },
    balance: { retrieve: vi.fn().mockResolvedValue({ object: "balance", livemode: true }) },
    products: { create: vi.fn().mockResolvedValue(product), retrieve: vi.fn().mockResolvedValue(product) },
    prices: { create: vi.fn().mockResolvedValue(price) }
  };
  return { publisher: new ProductPublisher(store, client), client, store };
}

describe("Stripe product publication", () => {
  it("publishes using the verified live OAuth binding and rejects other connections before claiming", async () => {
    const { client, store } = setup();
    const binding = { connectionId: initial.connectionId, accountId: initial.stripeAccountId };
    const wrong = new ProductPublisher(store, client, { ...binding, connectionId: "different" });
    await expect(wrong.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(store.claimProduct).not.toHaveBeenCalled();
    await expect(new ProductPublisher(store, client, binding).resume(actor, businessId, publicationId))
      .resolves.toEqual({ productId: product.id, priceId: price.id });
    expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
    expect(client.balance.retrieve).not.toHaveBeenCalled();
  });

  it("creates and records a live product and one-time price with separate idempotency keys", async () => {
    const { publisher, store, client } = setup();
    await expect(publisher.begin(actor, businessId, initial.draftId, "LIVE"))
      .resolves.toEqual({ publicationId });
    expect(client.products.create).not.toHaveBeenCalled();
    await expect(publisher.resume(actor, businessId, publicationId))
      .resolves.toEqual({ productId: "prod_123", priceId: "price_123" });
    expect(store.begin).toHaveBeenCalledWith(actor, businessId, initial.draftId, "LIVE");
    expect(client.products.create).toHaveBeenCalledWith({
      name: "Service", description: "Description",
      metadata: { kuzushi_publication_id: publicationId, kuzushi_kind: "SERVICE" }
    }, { idempotencyKey: `kp-product-${publicationId}` });
    expect(client.prices.create).toHaveBeenCalledWith({
      product: "prod_123", currency: "usd", unit_amount: 5000,
      metadata: { kuzushi_publication_id: publicationId }
    }, { idempotencyKey: `kp-price-${publicationId}` });
    expect(store.recordProduct).toHaveBeenCalledWith(publicationId, operationId, "prod_123");
    expect(store.recordPrice).toHaveBeenCalledWith(publicationId, operationId, "price_123");
  });

  it("creates a recurring price with the exact snapshot interval", async () => {
    const { publisher, client } = setup({ ...initial, billing: "RECURRING", interval: "MONTH" });
    client.prices.create.mockResolvedValue({
      ...price, type: "recurring",
      recurring: { interval: "month", interval_count: 1, usage_type: "licensed", trial_period_days: null }
    });
    await expect(publisher.resume(actor, businessId, publicationId)).resolves.toHaveProperty("priceId", "price_123");
    expect(client.prices.create.mock.calls[0][0].recurring).toEqual({ interval: "month", interval_count: 1 });
  });

  it("fails before claiming if the account, mode, or provider access does not match", async () => {
    for (const mismatch of ["account", "mode", "provider"] as const) {
      const { publisher, client, store } = setup();
      if (mismatch === "account") client.accounts.retrieveCurrent.mockResolvedValue({ object: "account", id: "acct_other" });
      if (mismatch === "mode") client.balance.retrieve.mockResolvedValue({ object: "balance", livemode: false });
      if (mismatch === "provider") client.balance.retrieve.mockRejectedValue(new Error("secret provider message"));
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
      expect(store.claimProduct).not.toHaveBeenCalled();
      expect(client.products.create).not.toHaveBeenCalled();
    }
  });

  it("never retries an uncertain product or price operation", async () => {
    for (const phase of ["product", "price"] as const) {
      const { publisher, client } = setup();
      if (phase === "product") client.products.create.mockRejectedValueOnce(new Error("provider details"));
      else client.prices.create.mockRejectedValueOnce(new Error("provider details"));
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
      expect(client.products.create).toHaveBeenCalledOnce();
      expect(client.prices.create).toHaveBeenCalledTimes(phase === "product" ? 0 : 1);
    }
  });

  it("treats a wrong response or failed persistence after dispatch as uncertain", async () => {
    for (const phase of ["response", "record"] as const) {
      const { publisher, client, store } = setup();
      if (phase === "response") client.products.create.mockResolvedValueOnce({ ...product, livemode: false });
      else store.recordProduct.mockResolvedValueOnce(false);
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
      expect(client.prices.create).not.toHaveBeenCalled();
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
    }
  });

  it("does not record a price that differs from the snapshot or publication", async () => {
    for (const badPrice of [
      { unit_amount: 1 }, { livemode: false }, { product: "prod_other" },
      { metadata: { kuzushi_publication_id: "other" } }, { type: "recurring" }
    ]) {
      const { publisher, client, store } = setup();
      client.prices.create.mockResolvedValueOnce({ ...price, ...badPrice });
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
      expect(store.recordPrice).not.toHaveBeenCalled();
      await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "OUTCOME_UNCERTAIN" });
      expect(client.prices.create).toHaveBeenCalledOnce();
    }
  });

  it("resumes a recorded product only after retrieving and verifying it", async () => {
    const { publisher, client } = setup({ ...initial, status: "PRODUCT_CREATED", stripeProductId: "prod_123" });
    client.products.retrieve.mockResolvedValueOnce({ ...product, active: false });
    await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "PREPARATION_FAILED" });
    expect(client.prices.create).not.toHaveBeenCalled();
    await expect(publisher.resume(actor, businessId, publicationId)).resolves.toHaveProperty("priceId", "price_123");
    expect(client.products.create).not.toHaveBeenCalled();
    expect(client.products.retrieve).toHaveBeenCalledTimes(2);
  });

  it("rejects a claim that differs from the authorized snapshot", async () => {
    const { publisher, client, store } = setup();
    store.claimProduct.mockResolvedValueOnce({ ...initial, status: "PRODUCT_CREATING", operationId, amountCents: 1 });
    await expect(publisher.resume(actor, businessId, publicationId)).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(client.products.create).not.toHaveBeenCalled();
  });

  it("sends the expected SDK requests to loopback", async () => {
    const requests: { url: string | undefined; body: string; key: string | string[] | undefined }[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        requests.push({ url: req.url, body: Buffer.concat(chunks).toString(), key: req.headers["idempotency-key"] });
        const response = req.url === "/v1/account" ? { id: "acct_123", object: "account" } :
          req.url === "/v1/balance" ? { object: "balance", livemode: true } :
          req.url === "/v1/products" ? product : price;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(response));
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing test server address");
      const stripe = new Stripe("rk_live_placeholder", {
        host: "127.0.0.1", port: address.port, protocol: "http",
        apiVersion: "2026-10-28.endive", maxNetworkRetries: 0
      });
      const { store } = setup();
      const publisher = new ProductPublisher(store, stripe);
      await expect(publisher.resume(actor, businessId, publicationId)).resolves.toHaveProperty("priceId", "price_123");
      expect(requests.map((request) => request.url)).toEqual(["/v1/account", "/v1/balance", "/v1/products", "/v1/prices"]);
      expect(requests[2].key).toBe(`kp-product-${publicationId}`);
      expect(requests[3].key).toBe(`kp-price-${publicationId}`);
      expect(new URLSearchParams(requests[3].body).get("unit_amount")).toBe("5000");
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
