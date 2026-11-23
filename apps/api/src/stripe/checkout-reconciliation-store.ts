import type {
  CheckoutAttempt, CheckoutOrder, StripeCheckoutEvent, StripePublication
} from "../generated/prisma/client.js";

export type CheckoutAttemptReconciliationContext = {
  order: CheckoutOrder;
  attempt: CheckoutAttempt;
  publication: StripePublication;
};
export type CheckoutReconciliationContext = CheckoutAttemptReconciliationContext & { event: StripeCheckoutEvent };
export type CheckoutObservation = { status: "UNPAID"; quantity: null } | { status: "PAID"; quantity: number };
export interface CheckoutReconciliationStore {
  find(businessId: string, connectionId: string, eventId: string): Promise<CheckoutReconciliationContext | null>;
  record(businessId: string, connectionId: string, eventId: string, orderId: string, observation: CheckoutObservation): Promise<void>;
  findAttempt(businessId: string, connectionId: string, attemptId: string): Promise<CheckoutAttemptReconciliationContext | null>;
  recordAttempt(
    businessId: string, connectionId: string, attemptId: string, orderId: string, sessionId: string,
    observation: CheckoutObservation
  ): Promise<void>;
}
