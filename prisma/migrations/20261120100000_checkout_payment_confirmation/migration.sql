CREATE TYPE "InitialCheckoutPaymentStatus" AS ENUM ('UNPAID', 'PAID');
ALTER TABLE "CheckoutOrder"
  ADD COLUMN "initialPaymentStatus" "InitialCheckoutPaymentStatus" NOT NULL DEFAULT 'UNPAID',
  ADD COLUMN "paidQuantity" INTEGER,
  ADD CONSTRAINT "CheckoutOrder_initial_payment_check" CHECK (
    ("initialPaymentStatus" = 'UNPAID' AND "paidQuantity" IS NULL) OR
    ("initialPaymentStatus" = 'PAID' AND "paidQuantity" IS NOT NULL AND "paidQuantity" BETWEEN 1 AND 50)
  );

CREATE OR REPLACE FUNCTION "protect_checkout_order"() RETURNS trigger AS $$
BEGIN
  IF (NEW."id", NEW."publicationId", NEW."createdAt") IS DISTINCT FROM
     (OLD."id", OLD."publicationId", OLD."createdAt") THEN
    RAISE EXCEPTION 'Checkout order snapshots are immutable';
  END IF;
  IF OLD."initialPaymentStatus" = 'PAID' AND
     (NEW."initialPaymentStatus", NEW."paidQuantity") IS DISTINCT FROM
     (OLD."initialPaymentStatus", OLD."paidQuantity") THEN
    RAISE EXCEPTION 'Initial checkout payment confirmation cannot be reversed';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE "StripeCheckoutEventResult" (
  "eventId" TEXT NOT NULL,
  "orderId" TEXT NOT NULL,
  "observedStatus" "InitialCheckoutPaymentStatus" NOT NULL,
  "processedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "StripeCheckoutEventResult_pkey" PRIMARY KEY ("eventId"),
  CONSTRAINT "StripeCheckoutEventResult_eventId_fkey" FOREIGN KEY ("eventId")
    REFERENCES "StripeCheckoutEvent"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "StripeCheckoutEventResult_orderId_fkey" FOREIGN KEY ("orderId")
    REFERENCES "CheckoutOrder"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE INDEX "StripeCheckoutEventResult_orderId_idx" ON "StripeCheckoutEventResult"("orderId");

CREATE FUNCTION "protect_stripe_checkout_event_result"() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Stripe checkout event results are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "StripeCheckoutEventResult_immutable"
BEFORE UPDATE ON "StripeCheckoutEventResult" FOR EACH ROW EXECUTE FUNCTION "protect_stripe_checkout_event_result"();
