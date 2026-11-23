CREATE TYPE "CheckoutEventWorkStatus" AS ENUM ('PENDING', 'PROCESSING', 'DONE');

CREATE TABLE "StripeCheckoutEventWork" (
  "eventId" TEXT NOT NULL,
  "status" "CheckoutEventWorkStatus" NOT NULL DEFAULT 'PENDING',
  "attemptCount" INTEGER NOT NULL DEFAULT 0,
  "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "leaseToken" TEXT,
  "leaseUntil" TIMESTAMP(3),
  "lastError" TEXT,
  CONSTRAINT "StripeCheckoutEventWork_pkey" PRIMARY KEY ("eventId"),
  CONSTRAINT "StripeCheckoutEventWork_eventId_fkey" FOREIGN KEY ("eventId")
    REFERENCES "StripeCheckoutEvent"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "StripeCheckoutEventWork_attempt_check" CHECK ("attemptCount" >= 0),
  CONSTRAINT "StripeCheckoutEventWork_lease_check" CHECK (
    ("status" = 'PROCESSING' AND "leaseToken" IS NOT NULL AND "leaseUntil" IS NOT NULL) OR
    ("status" IN ('PENDING', 'DONE') AND "leaseToken" IS NULL AND "leaseUntil" IS NULL)
  ),
  CONSTRAINT "StripeCheckoutEventWork_error_check" CHECK (
    "lastError" IS NULL OR "lastError" IN ('NOT_READY', 'STRIPE_UNAVAILABLE', 'INVALID_STRIPE_RESPONSE', 'INTERNAL_ERROR')
  )
);
CREATE INDEX "StripeCheckoutEventWork_status_nextAttemptAt_idx"
  ON "StripeCheckoutEventWork"("status", "nextAttemptAt");

-- Existing events may have been observed without a worker; recheck all of them.
INSERT INTO "StripeCheckoutEventWork" ("eventId")
SELECT "id" FROM "StripeCheckoutEvent";
