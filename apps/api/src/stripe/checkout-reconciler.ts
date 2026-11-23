import { z } from "zod";
import { checkoutInputSchema } from "./embedded-checkout.js";
import { matchesStripePrice, type StripePrice } from "./price.js";
import type { StripeCheckoutEvent } from "../generated/prisma/client.js";
import type {
  CheckoutAttemptReconciliationContext, CheckoutObservation, CheckoutReconciliationStore
} from "./checkout-reconciliation-store.js";

type Session = {
  id: string; object: string; livemode: boolean; status: string | null;
  mode: string; ui_mode: string | null; payment_status: string; currency: string | null;
  amount_total: number | null; automatic_tax: { enabled: boolean }; metadata: Record<string, string> | null;
};
type LineItems = {
  object: string; has_more: boolean;
  data: { object: string; quantity: number | null; currency: string; price: StripePrice | null }[];
};
export type ReconciliationClient = {
  accounts: { retrieveCurrent(): Promise<{ id: string; object: string }> };
  checkout: {
    sessions: {
      retrieve(id: string): Promise<Session>;
      listLineItems(id: string, params: { limit: number }): Promise<LineItems>;
    };
  };
};
export type ReconciliationSource = ReconciliationClient | {
  loadLiveClient(accountId: string): Promise<Pick<ReconciliationClient, "checkout">>;
};

export class CheckoutReconciliationError extends Error {
  constructor(readonly code: "NOT_READY" | "STRIPE_UNAVAILABLE" | "INVALID_STRIPE_RESPONSE") {
    super(code);
  }
}

type SessionStatus = "open" | "complete" | "expired";
type SessionObservation = { observedStatus: "UNPAID" | "PAID"; sessionStatus: SessionStatus };

export class CheckoutReconciler {
  constructor(
    private readonly store: CheckoutReconciliationStore,
    private readonly source: ReconciliationSource,
    private readonly businessId: string,
    private readonly connectionId: string
  ) {
    if (!z.string().uuid().safeParse(businessId).success || !z.string().uuid().safeParse(connectionId).success) {
      throw new Error("Invalid checkout reconciliation configuration");
    }
  }

  async reconcile(eventId: string): Promise<{ observedStatus: "UNPAID" | "PAID" }> {
    if (!/^evt_[A-Za-z0-9]+$/.test(eventId)) throw new CheckoutReconciliationError("NOT_READY");
    const context = await this.store.find(this.businessId, this.connectionId, eventId);
    if (!context) throw new CheckoutReconciliationError("NOT_READY");
    if (context.event.id !== eventId) throw new CheckoutReconciliationError("NOT_READY");
    const result = await this.observe(context, context.event);
    return { observedStatus: result.observedStatus };
  }

  async reconcileAttempt(attemptId: string): Promise<SessionObservation> {
    if (!z.string().uuid().safeParse(attemptId).success) throw new CheckoutReconciliationError("NOT_READY");
    const context = await this.store.findAttempt(this.businessId, this.connectionId, attemptId);
    if (!context || context.attempt.id !== attemptId) throw new CheckoutReconciliationError("NOT_READY");
    return this.observe(context);
  }

  private async observe(
    { attempt, order, publication }: CheckoutAttemptReconciliationContext,
    event?: StripeCheckoutEvent
  ): Promise<SessionObservation> {
    const input = checkoutInputSchema.safeParse({
      orderId: order.id, attemptId: attempt.id, priceId: publication.stripePriceId,
      productId: publication.stripeProductId, amountCents: publication.amountCents,
      billing: publication.billing, interval: publication.interval
    });
    const sessionId = attempt.stripeSessionId;
    const sessionPrefix = publication.mode === "LIVE" ? "cs_live_" : "cs_test_";
    if (!input.success || publication.businessId !== this.businessId ||
        publication.connectionId !== this.connectionId || attempt.orderId !== order.id ||
        order.publicationId !== publication.id || attempt.status !== "SESSION_CREATED" ||
        !sessionId || !sessionId.startsWith(sessionPrefix) || !/^cs_(?:test|live)_[A-Za-z0-9]+$/.test(sessionId) ||
        !/^acct_[A-Za-z0-9]+$/.test(publication.stripeAccountId) ||
        (event && (event.businessId !== this.businessId || event.connectionId !== this.connectionId ||
          publication.stripeAccountId !== event.stripeAccountId || publication.mode !== event.mode ||
          sessionId !== event.sessionId))) {
      throw new CheckoutReconciliationError("NOT_READY");
    }
    const record = (observation: CheckoutObservation) => event
      ? this.store.record(this.businessId, this.connectionId, event.id, order.id, observation)
      : this.store.recordAttempt(this.businessId, this.connectionId, attempt.id, order.id, sessionId, observation);

    if ("loadLiveClient" in this.source && publication.mode !== "LIVE") {
      throw new CheckoutReconciliationError("NOT_READY");
    }
    let client: Pick<ReconciliationClient, "checkout">;
    let accountId: string | undefined;
    let session: Session;
    try {
      if ("loadLiveClient" in this.source) {
        client = await this.source.loadLiveClient(publication.stripeAccountId);
        accountId = publication.stripeAccountId;
      } else {
        const account = await this.source.accounts.retrieveCurrent();
        accountId = account?.object === "account" ? account.id : undefined;
        client = this.source;
      }
      session = await client.checkout.sessions.retrieve(sessionId);
    } catch {
      throw new CheckoutReconciliationError("STRIPE_UNAVAILABLE");
    }
    const sessionStatus = z.enum(["open", "complete", "expired"]).safeParse(session?.status);
    if (accountId !== publication.stripeAccountId ||
        !session || session.object !== "checkout.session" || session.id !== sessionId ||
        session.livemode !== (publication.mode === "LIVE") || session.currency !== "usd" ||
        session.mode !== (input.data.billing === "ONE_TIME" ? "payment" : "subscription") ||
        session.ui_mode !== "embedded_page" || session.automatic_tax?.enabled !== true ||
        session.metadata?.kuzushi_order_id !== order.id || session.metadata?.kuzushi_attempt_id !== attempt.id ||
        !sessionStatus.success ||
        !["unpaid", "paid"].includes(session.payment_status)) {
      throw new CheckoutReconciliationError("INVALID_STRIPE_RESPONSE");
    }
    if ((event?.type === "checkout.session.async_payment_succeeded" && session.payment_status !== "paid") ||
        (event?.type === "checkout.session.completed" && session.status === "open") ||
        (session.payment_status === "paid" && session.status !== "complete")) {
      throw new CheckoutReconciliationError("NOT_READY");
    }

    if (session.payment_status === "unpaid") {
      await record({ status: "UNPAID", quantity: null });
      return { observedStatus: "UNPAID", sessionStatus: sessionStatus.data };
    }

    let lines: LineItems;
    try {
      lines = await client.checkout.sessions.listLineItems(session.id, { limit: 2 });
    } catch {
      throw new CheckoutReconciliationError("STRIPE_UNAVAILABLE");
    }
    const line = lines?.data?.[0];
    if (!lines || lines.object !== "list" || lines.has_more !== false || !Array.isArray(lines.data) || lines.data.length !== 1 ||
        !line || line.object !== "item" || line.currency !== "usd" ||
        typeof line.quantity !== "number" || !Number.isInteger(line.quantity) || line.quantity < 1 || line.quantity > 50 ||
        !line.price || !matchesStripePrice(line.price, { ...input.data, mode: publication.mode }, { allowInactive: true }) ||
        typeof session.amount_total !== "number" || !Number.isSafeInteger(session.amount_total) || session.amount_total < 1) {
      throw new CheckoutReconciliationError("INVALID_STRIPE_RESPONSE");
    }
    await record({ status: "PAID", quantity: line.quantity });
    return { observedStatus: "PAID", sessionStatus: sessionStatus.data };
  }
}
