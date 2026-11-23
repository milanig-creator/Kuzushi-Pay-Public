import type { CheckoutAttempt, CheckoutOrder, StripePublication } from "../generated/prisma/client.js";

export type CheckoutClaim = {
  attempt: CheckoutAttempt;
  order: CheckoutOrder;
  publication: StripePublication;
  storefront?: { origin: string; returnUrl: string };
};
export type CheckoutStorefront =
  | { origin: string; revision: string; mode?: "TEST"; connectionId?: string; requestId?: string }
  | { origin: string; revision: string; mode: "LIVE"; connectionId: string; requestId: string }
  | { origin: string; revision: null; mode: "LIVE"; connectionId: string; requestId: string; dashboardReturnUrl: string };

export interface CheckoutStore {
  begin(businessId: string, publicationId: string, setup?: CheckoutStorefront): Promise<{ orderId: string; attemptId: string } | null>;
  claim(businessId: string, attemptId: string, setup?: CheckoutStorefront): Promise<CheckoutClaim | null>;
  recordSession(attemptId: string, operationId: string, sessionId: string): Promise<boolean>;
}
