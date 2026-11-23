CREATE TABLE "CheckoutRecoveryWork" (
  "attemptId" TEXT NOT NULL,
  "status" "CheckoutEventWorkStatus" NOT NULL DEFAULT 'PENDING',
  "attemptCount" INTEGER NOT NULL DEFAULT 0,
  "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "leaseToken" TEXT,
  "leaseUntil" TIMESTAMP(3),
  "lastError" TEXT,
  CONSTRAINT "CheckoutRecoveryWork_pkey" PRIMARY KEY ("attemptId"),
  CONSTRAINT "CheckoutRecoveryWork_attemptId_fkey" FOREIGN KEY ("attemptId")
    REFERENCES "CheckoutAttempt"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "CheckoutRecoveryWork_attempt_check" CHECK ("attemptCount" >= 0),
  CONSTRAINT "CheckoutRecoveryWork_lease_check" CHECK (
    ("status" = 'PROCESSING' AND "leaseToken" IS NOT NULL AND "leaseUntil" IS NOT NULL) OR
    ("status" IN ('PENDING', 'DONE') AND "leaseToken" IS NULL AND "leaseUntil" IS NULL)
  ),
  CONSTRAINT "CheckoutRecoveryWork_error_check" CHECK (
    "lastError" IS NULL OR "lastError" IN ('NOT_READY', 'STRIPE_UNAVAILABLE', 'INVALID_STRIPE_RESPONSE', 'INTERNAL_ERROR')
  )
);
CREATE INDEX "CheckoutRecoveryWork_status_nextAttemptAt_idx"
  ON "CheckoutRecoveryWork"("status", "nextAttemptAt");

INSERT INTO "CheckoutRecoveryWork" ("attemptId", "status")
SELECT a."id", CASE WHEN o."initialPaymentStatus" = 'PAID'
  THEN 'DONE'::"CheckoutEventWorkStatus" ELSE 'PENDING'::"CheckoutEventWorkStatus" END
FROM "CheckoutAttempt" a JOIN "CheckoutOrder" o ON o."id" = a."orderId"
WHERE a."status" = 'SESSION_CREATED';
