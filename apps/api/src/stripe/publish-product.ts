import type Stripe from "stripe";
import { z } from "zod";
import type { User } from "../repository.js";
import { matchesStripePrice, type StripePrice } from "./price.js";
import type { PublicationStore } from "./publication-store.js";

type Product = {
  id: string; object: string; livemode: boolean; active: boolean; name: string;
  description: string | null; metadata: Record<string, string>;
};

export type PublicationClient = {
  accounts: { retrieveCurrent(): Promise<{ id: string; object: string }> };
  balance: { retrieve(): Promise<{ object: string; livemode: boolean }> };
  products: {
    retrieve(id: string): Promise<Product>;
    create(params: Stripe.ProductCreateParams, options: Stripe.RequestOptions): Promise<Product>;
  };
  prices: {
    create(params: Stripe.PriceCreateParams, options: Stripe.RequestOptions): Promise<StripePrice & { metadata: Record<string, string> }>;
  };
};

const snapshotSchema = z.object({
  id: z.string().uuid(), draftId: z.string().uuid(), businessId: z.string().uuid(),
  connectionId: z.string().uuid(), actorId: z.string().uuid(),
  actorSessionVersion: z.number().int().nonnegative(), mode: z.enum(["TEST", "LIVE"]),
  stripeAccountId: z.string().regex(/^acct_[A-Za-z0-9]+$/),
  name: z.string().min(1).max(120), description: z.string().max(500),
  kind: z.enum(["PHYSICAL", "DIGITAL", "SERVICE"]),
  amountCents: z.number().int().min(1).max(99999999), currency: z.literal("USD"),
  billing: z.enum(["ONE_TIME", "RECURRING"]), interval: z.enum(["DAY", "WEEK", "MONTH", "YEAR"]).nullable(),
  status: z.enum(["PENDING", "PRODUCT_CREATING", "PRODUCT_CREATED", "PRICE_CREATING", "PRICE_CREATED"]),
  operationId: z.string().uuid().nullable(),
  stripeProductId: z.string().regex(/^prod_[A-Za-z0-9]+$/).nullable(),
  stripePriceId: z.string().regex(/^price_[A-Za-z0-9]+$/).nullable()
}).refine((value) => value.billing === "ONE_TIME" ? value.interval === null : value.interval !== null);
type Snapshot = z.output<typeof snapshotSchema>;

export class PublicationError extends Error {
  constructor(readonly code: "UNAVAILABLE" | "PREPARATION_FAILED" | "OUTCOME_UNCERTAIN") {
    super(code);
  }
}

function sameSnapshot(a: Snapshot, b: Snapshot): boolean {
  const { status: _statusA, operationId: _operationA, stripeProductId: _productA, stripePriceId: _priceA, ...first } = a;
  const { status: _statusB, operationId: _operationB, stripeProductId: _productB, stripePriceId: _priceB, ...second } = b;
  return JSON.stringify(first) === JSON.stringify(second);
}

function matchesProduct(product: Product, snapshot: Snapshot): boolean {
  return !!product && product.object === "product" && typeof product.id === "string" &&
    /^prod_[A-Za-z0-9]+$/.test(product.id) && product.livemode === (snapshot.mode === "LIVE") &&
    product.active === true && product.name === snapshot.name && (product.description ?? "") === snapshot.description &&
    product.metadata?.kuzushi_publication_id === snapshot.id && product.metadata?.kuzushi_kind === snapshot.kind;
}

export class ProductPublisher {
  constructor(private readonly store: PublicationStore, private readonly client: PublicationClient,
    private readonly oauthBinding?: { connectionId: string; accountId: string }) {}

  async begin(actor: User, businessId: string, draftId: string, mode: "TEST" | "LIVE") {
    const snapshot = await this.store.begin(actor, businessId, draftId, mode);
    if (!snapshot) throw new PublicationError("UNAVAILABLE");
    return { publicationId: snapshot.id };
  }

  async resume(actor: User, businessId: string, id: string): Promise<{ productId: string; priceId: string }> {
    const parsed = snapshotSchema.safeParse(await this.store.find(actor, businessId, id));
    if (!parsed.success || parsed.data.id !== id || parsed.data.businessId !== businessId ||
        parsed.data.actorId !== actor.id || parsed.data.actorSessionVersion !== actor.sessionVersion) {
      throw new PublicationError("UNAVAILABLE");
    }
    let snapshot = parsed.data;
    if (snapshot.status === "PRODUCT_CREATING" || snapshot.status === "PRICE_CREATING") {
      throw new PublicationError("OUTCOME_UNCERTAIN");
    }
    if (snapshot.status === "PRICE_CREATED" && snapshot.stripeProductId && snapshot.stripePriceId) {
      return { productId: snapshot.stripeProductId, priceId: snapshot.stripePriceId };
    }
    try {
      if (this.oauthBinding) {
        if (snapshot.mode !== "LIVE" || this.oauthBinding.connectionId !== snapshot.connectionId ||
            this.oauthBinding.accountId !== snapshot.stripeAccountId) throw new Error("OAuth binding mismatch");
      } else {
        const account = await this.client.accounts.retrieveCurrent();
        const balance = await this.client.balance.retrieve();
        if (!account || account.object !== "account" || account.id !== snapshot.stripeAccountId ||
            !balance || balance.object !== "balance" || balance.livemode !== (snapshot.mode === "LIVE")) {
          throw new Error("Account or mode mismatch");
        }
      }
    } catch {
      throw new PublicationError("PREPARATION_FAILED");
    }

    let productId: string;
    if (snapshot.status === "PENDING") {
      const claimed = snapshotSchema.safeParse(await this.store.claimProduct(id));
      if (!claimed.success || !sameSnapshot(snapshot, claimed.data) ||
          claimed.data.status !== "PRODUCT_CREATING" || !claimed.data.operationId ||
          claimed.data.stripeProductId || claimed.data.stripePriceId) throw new PublicationError("UNAVAILABLE");
      const operationId = claimed.data.operationId;
      snapshot = claimed.data;
      try {
        const product = await this.client.products.create({
          name: snapshot.name, ...(snapshot.description ? { description: snapshot.description } : {}),
          metadata: { kuzushi_publication_id: snapshot.id, kuzushi_kind: snapshot.kind }
        }, { idempotencyKey: `kp-product-${snapshot.id}` });
        if (!matchesProduct(product, snapshot) ||
            !await this.store.recordProduct(id, operationId, product.id)) throw new Error("Product outcome unrecorded");
        productId = product.id;
      } catch {
        throw new PublicationError("OUTCOME_UNCERTAIN");
      }
    } else if (snapshot.status === "PRODUCT_CREATED" && snapshot.stripeProductId && !snapshot.stripePriceId) {
      productId = snapshot.stripeProductId;
      try {
        const product = await this.client.products.retrieve(productId);
        if (product.id !== productId || !matchesProduct(product, snapshot)) throw new Error("Product mismatch");
      } catch {
        throw new PublicationError("PREPARATION_FAILED");
      }
    } else {
      throw new PublicationError("UNAVAILABLE");
    }

    const priceClaim = snapshotSchema.safeParse(await this.store.claimPrice(id));
    if (!priceClaim.success || !sameSnapshot(snapshot, priceClaim.data) ||
        priceClaim.data.status !== "PRICE_CREATING" || !priceClaim.data.operationId ||
        priceClaim.data.stripeProductId !== productId || priceClaim.data.stripePriceId) throw new PublicationError("UNAVAILABLE");
    const operationId = priceClaim.data.operationId;
    snapshot = priceClaim.data;
    const intervals = { DAY: "day", WEEK: "week", MONTH: "month", YEAR: "year" } as const;
    const recurring = snapshot.billing === "RECURRING" && snapshot.interval
      ? { interval: intervals[snapshot.interval], interval_count: 1 } : undefined;
    try {
      const price = await this.client.prices.create({
        product: productId, currency: "usd", unit_amount: snapshot.amountCents,
        ...(recurring ? { recurring } : {}), metadata: { kuzushi_publication_id: snapshot.id }
      }, { idempotencyKey: `kp-price-${snapshot.id}` });
      if (!matchesStripePrice(price, { ...snapshot, productId }) ||
          price.metadata?.kuzushi_publication_id !== snapshot.id ||
          !await this.store.recordPrice(id, operationId, price.id)) throw new Error("Price outcome unrecorded");
      return { productId, priceId: price.id };
    } catch {
      throw new PublicationError("OUTCOME_UNCERTAIN");
    }
  }
}
