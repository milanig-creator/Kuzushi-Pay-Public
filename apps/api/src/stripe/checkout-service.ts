import { z } from "zod";
import {
  checkoutInputSchema, EmbeddedCheckout, EmbeddedCheckoutError, validCheckoutReturnUrl,
  type EmbeddedCheckoutClient
} from "./embedded-checkout.js";
import type { CheckoutStore, CheckoutStorefront } from "./checkout-store.js";

export class CheckoutServiceError extends Error {
  constructor(readonly code: "UNAVAILABLE" | "PREPARATION_FAILED" | "OUTCOME_UNCERTAIN") {
    super(code);
  }
}

export class CheckoutService {
  constructor(
    private readonly store: CheckoutStore,
    private readonly client: EmbeddedCheckoutClient,
    private readonly businessId: string,
    private readonly storefront: string | CheckoutStorefront,
    private readonly returnUrl?: string,
    private readonly oauthBinding?: { connectionId: string; accountId: string }
  ) {
    const validStorefront = typeof storefront === "string"
      ? !!returnUrl && validCheckoutReturnUrl(storefront, returnUrl)
      : storefront.revision === null
        ? validCheckoutReturnUrl(storefront.origin, storefront.dashboardReturnUrl)
        : z.uuid().safeParse(storefront.revision).success;
    const liveStorefront = typeof storefront !== "string" && storefront.mode === "LIVE" ? storefront : undefined;
    const validLiveBinding = liveStorefront ? oauthBinding?.connectionId === liveStorefront.connectionId &&
      z.uuid().safeParse(liveStorefront.connectionId).success && z.uuid().safeParse(liveStorefront.requestId).success &&
      /^acct_[A-Za-z0-9]+$/.test(oauthBinding.accountId) : !oauthBinding;
    if (!z.uuid().safeParse(businessId).success || !validStorefront || !validLiveBinding) {
      throw new Error("Invalid embedded checkout configuration");
    }
  }

  async begin(publicationId: string) {
    if (!z.string().uuid().safeParse(publicationId).success) throw new CheckoutServiceError("UNAVAILABLE");
    const result = typeof this.storefront === "string"
      ? await this.store.begin(this.businessId, publicationId)
      : await this.store.begin(this.businessId, publicationId, this.storefront);
    if (!result) throw new CheckoutServiceError("UNAVAILABLE");
    return result;
  }

  async create(attemptId: string): Promise<{ clientSecret: string }> {
    if (!z.string().uuid().safeParse(attemptId).success) throw new CheckoutServiceError("UNAVAILABLE");
    const claim = typeof this.storefront === "string"
      ? await this.store.claim(this.businessId, attemptId)
      : await this.store.claim(this.businessId, attemptId, this.storefront);
    if (!claim) throw new CheckoutServiceError("UNAVAILABLE");
    const { attempt, order, publication } = claim;
    const storefront = typeof this.storefront === "string"
      ? { origin: this.storefront, returnUrl: this.returnUrl }
      : claim.storefront;
    if (!storefront?.returnUrl || (typeof this.storefront !== "string" &&
        (publication.mode !== (this.storefront.mode ?? "TEST") || order.storefrontRevision !== this.storefront.revision ||
          storefront.origin !== this.storefront.origin ||
          (this.storefront.revision === null && storefront.returnUrl !== this.storefront.dashboardReturnUrl) ||
          (this.storefront.mode === "LIVE" && order.storefrontRequestId !== this.storefront.requestId)))) {
      throw new CheckoutServiceError("UNAVAILABLE");
    }
    const input = checkoutInputSchema.safeParse({
      orderId: order.id, attemptId: attempt.id, priceId: publication.stripePriceId,
      productId: publication.stripeProductId, amountCents: publication.amountCents,
      billing: publication.billing, interval: publication.interval
    });
    if (!input.success || attempt.id !== attemptId || attempt.orderId !== order.id ||
        order.publicationId !== publication.id || attempt.status !== "CREATING" || !attempt.operationId ||
        publication.businessId !== this.businessId || publication.status !== "PRICE_CREATED" ||
        !/^acct_[A-Za-z0-9]+$/.test(publication.stripeAccountId) ||
        (this.oauthBinding && (publication.connectionId !== this.oauthBinding.connectionId ||
          publication.stripeAccountId !== this.oauthBinding.accountId))) {
      throw new CheckoutServiceError("PREPARATION_FAILED");
    }
    const gateway = new EmbeddedCheckout(
      this.client, publication.stripeAccountId, publication.mode, storefront.origin, storefront.returnUrl, this.oauthBinding?.accountId
    );
    let result: { sessionId: string; clientSecret: string };
    try {
      result = await gateway.create(input.data);
    } catch (error) {
      if (error instanceof EmbeddedCheckoutError && error.code !== "OUTCOME_UNCERTAIN") {
        throw new CheckoutServiceError("PREPARATION_FAILED");
      }
      throw new CheckoutServiceError("OUTCOME_UNCERTAIN");
    }
    try {
      if (!await this.store.recordSession(attemptId, attempt.operationId, result.sessionId)) {
        throw new Error("Session outcome unrecorded");
      }
    } catch {
      throw new CheckoutServiceError("OUTCOME_UNCERTAIN");
    }
    return { clientSecret: result.clientSecret };
  }
}
