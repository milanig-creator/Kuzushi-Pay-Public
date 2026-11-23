CREATE TABLE "ProductDraft" (
  "id" TEXT NOT NULL,
  "businessId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "description" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "amountCents" INTEGER NOT NULL,
  "currency" TEXT NOT NULL DEFAULT 'USD',
  "billing" TEXT NOT NULL,
  "interval" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ProductDraft_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ProductDraft_name_check" CHECK (length(trim("name")) BETWEEN 1 AND 120),
  CONSTRAINT "ProductDraft_description_check" CHECK (length("description") <= 500),
  CONSTRAINT "ProductDraft_kind_check" CHECK ("kind" IN ('PHYSICAL', 'DIGITAL', 'SERVICE')),
  CONSTRAINT "ProductDraft_amount_check" CHECK ("amountCents" BETWEEN 1 AND 99999999),
  CONSTRAINT "ProductDraft_currency_check" CHECK ("currency" = 'USD'),
  CONSTRAINT "ProductDraft_billing_check" CHECK (
    ("billing" = 'ONE_TIME' AND "interval" IS NULL) OR
    ("billing" = 'RECURRING' AND "interval" IS NOT NULL AND "interval" IN ('DAY', 'WEEK', 'MONTH', 'YEAR'))
  ),
  CONSTRAINT "ProductDraft_businessId_fkey" FOREIGN KEY ("businessId") REFERENCES "Business"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "ProductDraft_businessId_createdAt_idx" ON "ProductDraft"("businessId", "createdAt");
