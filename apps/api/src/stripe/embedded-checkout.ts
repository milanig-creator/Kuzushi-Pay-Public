import type Stripe from "stripe";
import { z } from "zod";
import { matchesStripePrice, type StripePrice } from "./price.js";

type Account = { id: string; object: string };
type CheckoutSession = {
  id: string; object: string; livemode: boolean; status: string | null;
  mode: string | null; ui_mode: string | null; currency: string | null;
  amount_subtotal: number | null; client_secret: string | null;
  automatic_tax: { enabled: boolean }; metadata: Record<string, string> | null;
};

export type EmbeddedCheckoutClient = {
  accounts: { retrieveCurrent(): Promise<Account> };
  prices: { retrieve(id: string): Promise<StripePrice> };
  checkout: {
    sessions: {
      create(params: Stripe.Checkout.SessionCreateParams, options: Stripe.RequestOptions): Promise<CheckoutSession>;
    };
  };
};

export const checkoutInputSchema = z.object({
  orderId: z.string().uuid(),
  attemptId: z.string().uuid(),
  priceId: z.string().regex(/^price_[A-Za-z0-9]+$/),
  productId: z.string().regex(/^prod_[A-Za-z0-9]+$/),
  amountCents: z.number().int().min(1).max(99999999),
  billing: z.enum(["ONE_TIME", "RECURRING"]),
  interval: z.enum(["DAY", "WEEK", "MONTH", "YEAR"]).nullable()
}).strict().refine((value) =>
  value.billing === "ONE_TIME" ? value.interval === null : value.interval !== null
);

export type EmbeddedCheckoutInput = z.input<typeof checkoutInputSchema>;

export function validCheckoutReturnUrl(storefrontOrigin: string, returnUrl: string): boolean {
  let origin: URL;
  let destination: URL;
  try {
    origin = new URL(storefrontOrigin);
    destination = new URL(returnUrl);
  } catch (error) {
    if (error instanceof TypeError) return false;
    throw error;
  }
  const params = [...destination.searchParams.entries()];
  return origin.protocol === "https:" && origin.origin === storefrontOrigin &&
    destination.origin === storefrontOrigin && !destination.username && !destination.password && !destination.hash &&
    params.length === 1 && params[0][0] === "session_id" && params[0][1] === "{CHECKOUT_SESSION_ID}" &&
    returnUrl.includes("{CHECKOUT_SESSION_ID}");
}

export class EmbeddedCheckoutError extends Error {
  constructor(readonly code: "INVALID_INPUT" | "PREPARATION_FAILED" | "OUTCOME_UNCERTAIN") {
    super(code);
  }
}

export class EmbeddedCheckout {
  private readonly returnUrl: string;

  constructor(
    private readonly client: EmbeddedCheckoutClient,
    private readonly accountId: string,
    private readonly mode: "TEST" | "LIVE",
    storefrontOrigin: string,
    returnUrl: string,
    private readonly oauthAccountId?: string
  ) {
    if (!/^acct_[A-Za-z0-9]+$/.test(accountId) || !["TEST", "LIVE"].includes(mode) ||
        !validCheckoutReturnUrl(storefrontOrigin, returnUrl) ||
        (oauthAccountId !== undefined && (mode !== "LIVE" || oauthAccountId !== accountId))) {
      throw new Error("Invalid embedded checkout configuration");
    }
    this.returnUrl = returnUrl;
  }

  async create(input: EmbeddedCheckoutInput) {
    const parsed = checkoutInputSchema.safeParse(input);
    if (!parsed.success) throw new EmbeddedCheckoutError("INVALID_INPUT");
    const snapshot = parsed.data;
    let accountId: string | undefined;
    let price: StripePrice;
    try {
      accountId = this.oauthAccountId;
      if (accountId === undefined) {
        const account = await this.client.accounts.retrieveCurrent();
        accountId = account?.object === "account" ? account.id : undefined;
      }
      price = await this.client.prices.retrieve(snapshot.priceId);
    } catch {
      throw new EmbeddedCheckoutError("PREPARATION_FAILED");
    }
    if (!price) throw new EmbeddedCheckoutError("PREPARATION_FAILED");
    const expectedMode = this.mode === "LIVE";
    const recurring = snapshot.billing === "RECURRING";
    if (accountId !== this.accountId ||
        !matchesStripePrice(price, { ...snapshot, mode: this.mode })) {
      throw new EmbeddedCheckoutError("PREPARATION_FAILED");
    }

    let session: CheckoutSession;
    try {
      session = await this.client.checkout.sessions.create({
        ui_mode: "embedded_page",
        mode: recurring ? "subscription" : "payment",
        line_items: [{ price: snapshot.priceId, quantity: 1, adjustable_quantity: { enabled: true, minimum: 1, maximum: 50 } }],
        automatic_tax: { enabled: true },
        adaptive_pricing: { enabled: false },
        return_url: this.returnUrl,
        metadata: { kuzushi_order_id: snapshot.orderId, kuzushi_attempt_id: snapshot.attemptId }
      }, { idempotencyKey: `kp-checkout-${snapshot.attemptId}` });
    } catch {
      throw new EmbeddedCheckoutError("OUTCOME_UNCERTAIN");
    }
    const prefix = this.mode === "LIVE" ? "cs_live_" : "cs_test_";
    if (!session || session.object !== "checkout.session" || typeof session.id !== "string" || !session.id.startsWith(prefix) ||
        !/^cs_(?:test|live)_[A-Za-z0-9]+$/.test(session.id) ||
        session.livemode !== expectedMode || session.status !== "open" ||
        session.mode !== (recurring ? "subscription" : "payment") || session.ui_mode !== "embedded_page" ||
        session.currency !== "usd" || session.amount_subtotal !== snapshot.amountCents ||
        session.automatic_tax?.enabled !== true || session.metadata?.kuzushi_order_id !== snapshot.orderId ||
        session.metadata?.kuzushi_attempt_id !== snapshot.attemptId ||
        typeof session.client_secret !== "string" || !session.client_secret.startsWith(`${session.id}_secret_`) ||
        session.client_secret.length <= `${session.id}_secret_`.length || /\s/.test(session.client_secret)) {
      throw new EmbeddedCheckoutError("OUTCOME_UNCERTAIN");
    }
    return { sessionId: session.id, clientSecret: session.client_secret };
  }
}
