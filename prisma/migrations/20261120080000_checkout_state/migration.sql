CREATE TYPE "CheckoutAttemptStatus" AS ENUM ('PENDING', 'CREATING', 'SESSION_CREATED');

CREATE TABLE "CheckoutOrder" (
  "id" TEXT NOT NULL,
  "publicationId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "CheckoutOrder_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "CheckoutOrder_publicationId_fkey" FOREIGN KEY ("publicationId") REFERENCES "StripePublication"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE INDEX "CheckoutOrder_publicationId_createdAt_idx" ON "CheckoutOrder"("publicationId", "createdAt");

CREATE TABLE "CheckoutAttempt" (
  "id" TEXT NOT NULL,
  "orderId" TEXT NOT NULL,
  "status" "CheckoutAttemptStatus" NOT NULL DEFAULT 'PENDING',
  "operationId" TEXT,
  "claimedAt" TIMESTAMP(3),
  "stripeSessionId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "CheckoutAttempt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "CheckoutAttempt_session_format" CHECK ("stripeSessionId" IS NULL OR "stripeSessionId" ~ '^cs_(test|live)_[A-Za-z0-9]+$'),
  CONSTRAINT "CheckoutAttempt_state_check" CHECK (
    ("status" = 'PENDING' AND "operationId" IS NULL AND "claimedAt" IS NULL AND "stripeSessionId" IS NULL) OR
    ("status" = 'CREATING' AND "operationId" IS NOT NULL AND "claimedAt" IS NOT NULL AND "stripeSessionId" IS NULL) OR
    ("status" = 'SESSION_CREATED' AND "operationId" IS NULL AND "claimedAt" IS NULL AND "stripeSessionId" IS NOT NULL)
  ),
  CONSTRAINT "CheckoutAttempt_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "CheckoutOrder"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "CheckoutAttempt_orderId_key" ON "CheckoutAttempt"("orderId");
CREATE UNIQUE INDEX "CheckoutAttempt_stripeSessionId_key" ON "CheckoutAttempt"("stripeSessionId");

CREATE FUNCTION "protect_checkout_order"() RETURNS trigger AS $$
BEGIN
  IF (NEW."id", NEW."publicationId", NEW."createdAt") IS DISTINCT FROM
     (OLD."id", OLD."publicationId", OLD."createdAt") THEN
    RAISE EXCEPTION 'Checkout order snapshots are immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "CheckoutOrder_immutable_snapshot"
BEFORE UPDATE ON "CheckoutOrder" FOR EACH ROW EXECUTE FUNCTION "protect_checkout_order"();

CREATE FUNCTION "protect_checkout_attempt"() RETURNS trigger AS $$
BEGIN
  IF (NEW."id", NEW."orderId", NEW."createdAt") IS DISTINCT FROM (OLD."id", OLD."orderId", OLD."createdAt") THEN
    RAISE EXCEPTION 'Checkout attempt identity is immutable';
  END IF;
  IF NEW."status" IS DISTINCT FROM OLD."status" AND NOT (
    (OLD."status" = 'PENDING' AND NEW."status" = 'CREATING') OR
    (OLD."status" = 'CREATING' AND NEW."status" = 'SESSION_CREATED')
  ) THEN
    RAISE EXCEPTION 'Invalid checkout attempt transition';
  END IF;
  IF NEW."status" = OLD."status" AND
     (NEW."operationId", NEW."claimedAt", NEW."stripeSessionId") IS DISTINCT FROM
     (OLD."operationId", OLD."claimedAt", OLD."stripeSessionId") THEN
    RAISE EXCEPTION 'Checkout state changes require a transition';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "CheckoutAttempt_protect_state"
BEFORE UPDATE ON "CheckoutAttempt" FOR EACH ROW EXECUTE FUNCTION "protect_checkout_attempt"();
