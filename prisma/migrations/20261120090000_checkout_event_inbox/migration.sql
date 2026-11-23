CREATE TABLE "StripeCheckoutEvent" (
  "id" TEXT NOT NULL,
  "connectionId" TEXT NOT NULL,
  "businessId" TEXT NOT NULL,
  "mode" "StripeMode" NOT NULL,
  "stripeAccountId" TEXT NOT NULL,
  "source" TEXT NOT NULL,
  "type" TEXT NOT NULL,
  "sessionId" TEXT NOT NULL,
  "eventCreated" BIGINT NOT NULL,
  "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "StripeCheckoutEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "StripeCheckoutEvent_id_check" CHECK ("id" ~ '^evt_[A-Za-z0-9]+$'),
  CONSTRAINT "StripeCheckoutEvent_source_check" CHECK ("source" IN ('direct', 'connected')),
  CONSTRAINT "StripeCheckoutEvent_type_check" CHECK ("type" IN (
    'checkout.session.completed', 'checkout.session.async_payment_succeeded',
    'checkout.session.async_payment_failed', 'checkout.session.expired'
  )),
  CONSTRAINT "StripeCheckoutEvent_session_check" CHECK (
    ("mode" = 'TEST' AND "sessionId" ~ '^cs_test_[A-Za-z0-9]+$') OR
    ("mode" = 'LIVE' AND "sessionId" ~ '^cs_live_[A-Za-z0-9]+$')
  ),
  CONSTRAINT "StripeCheckoutEvent_created_check" CHECK ("eventCreated" >= 0),
  CONSTRAINT "StripeCheckoutEvent_connectionId_businessId_mode_stripeAcc_fkey"
    FOREIGN KEY ("connectionId", "businessId", "mode", "stripeAccountId")
    REFERENCES "StripeConnection"("id", "businessId", "mode", "stripeAccountId")
    ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE INDEX "StripeCheckoutEvent_businessId_receivedAt_idx" ON "StripeCheckoutEvent"("businessId", "receivedAt");
CREATE INDEX "StripeCheckoutEvent_sessionId_idx" ON "StripeCheckoutEvent"("sessionId");

CREATE FUNCTION "protect_stripe_checkout_event"() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Stripe checkout events are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "StripeCheckoutEvent_immutable"
BEFORE UPDATE ON "StripeCheckoutEvent" FOR EACH ROW EXECUTE FUNCTION "protect_stripe_checkout_event"();
