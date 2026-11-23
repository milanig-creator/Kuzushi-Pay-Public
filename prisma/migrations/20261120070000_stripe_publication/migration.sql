CREATE TYPE "StripePublicationStatus" AS ENUM (
  'PENDING', 'PRODUCT_CREATING', 'PRODUCT_CREATED', 'PRICE_CREATING', 'PRICE_CREATED'
);

CREATE UNIQUE INDEX "ProductDraft_id_businessId_key" ON "ProductDraft"("id", "businessId");
CREATE UNIQUE INDEX "StripeConnection_id_businessId_mode_stripeAccountId_key" ON "StripeConnection"("id", "businessId", "mode", "stripeAccountId");

CREATE TABLE "StripePublication" (
  "id" TEXT NOT NULL,
  "draftId" TEXT NOT NULL,
  "businessId" TEXT NOT NULL,
  "actorId" TEXT NOT NULL,
  "actorSessionVersion" INTEGER NOT NULL,
  "connectionId" TEXT NOT NULL,
  "mode" "StripeMode" NOT NULL,
  "stripeAccountId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "description" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "amountCents" INTEGER NOT NULL,
  "currency" TEXT NOT NULL,
  "billing" TEXT NOT NULL,
  "interval" TEXT,
  "status" "StripePublicationStatus" NOT NULL DEFAULT 'PENDING',
  "operationId" TEXT,
  "claimedAt" TIMESTAMP(3),
  "stripeProductId" TEXT,
  "stripePriceId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "StripePublication_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "StripePublication_account_format" CHECK ("stripeAccountId" ~ '^acct_[A-Za-z0-9]+$'),
  CONSTRAINT "StripePublication_actor_version_check" CHECK ("actorSessionVersion" >= 0),
  CONSTRAINT "StripePublication_name_check" CHECK (length(trim("name")) BETWEEN 1 AND 120),
  CONSTRAINT "StripePublication_description_check" CHECK (length("description") <= 500),
  CONSTRAINT "StripePublication_kind_check" CHECK ("kind" IN ('PHYSICAL', 'DIGITAL', 'SERVICE')),
  CONSTRAINT "StripePublication_amount_check" CHECK ("amountCents" BETWEEN 1 AND 99999999),
  CONSTRAINT "StripePublication_currency_check" CHECK ("currency" = 'USD'),
  CONSTRAINT "StripePublication_billing_check" CHECK (
    ("billing" = 'ONE_TIME' AND "interval" IS NULL) OR
    ("billing" = 'RECURRING' AND "interval" IS NOT NULL AND "interval" IN ('DAY', 'WEEK', 'MONTH', 'YEAR'))
  ),
  CONSTRAINT "StripePublication_product_format" CHECK ("stripeProductId" IS NULL OR "stripeProductId" ~ '^prod_[A-Za-z0-9]+$'),
  CONSTRAINT "StripePublication_price_format" CHECK ("stripePriceId" IS NULL OR "stripePriceId" ~ '^price_[A-Za-z0-9]+$'),
  CONSTRAINT "StripePublication_state_check" CHECK (
    ("status" = 'PENDING' AND "operationId" IS NULL AND "claimedAt" IS NULL AND "stripeProductId" IS NULL AND "stripePriceId" IS NULL) OR
    ("status" = 'PRODUCT_CREATING' AND "operationId" IS NOT NULL AND "claimedAt" IS NOT NULL AND "stripeProductId" IS NULL AND "stripePriceId" IS NULL) OR
    ("status" = 'PRODUCT_CREATED' AND "operationId" IS NULL AND "claimedAt" IS NULL AND "stripeProductId" IS NOT NULL AND "stripePriceId" IS NULL) OR
    ("status" = 'PRICE_CREATING' AND "operationId" IS NOT NULL AND "claimedAt" IS NOT NULL AND "stripeProductId" IS NOT NULL AND "stripePriceId" IS NULL) OR
    ("status" = 'PRICE_CREATED' AND "operationId" IS NULL AND "claimedAt" IS NULL AND "stripeProductId" IS NOT NULL AND "stripePriceId" IS NOT NULL)
  ),
  CONSTRAINT "StripePublication_draftId_businessId_fkey" FOREIGN KEY ("draftId", "businessId") REFERENCES "ProductDraft"("id", "businessId") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "StripePublication_connectionId_businessId_mode_stripeAccou_fkey" FOREIGN KEY ("connectionId", "businessId", "mode", "stripeAccountId") REFERENCES "StripeConnection"("id", "businessId", "mode", "stripeAccountId") ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE UNIQUE INDEX "StripePublication_draftId_mode_key" ON "StripePublication"("draftId", "mode");
CREATE UNIQUE INDEX "StripePublication_mode_stripeProductId_key" ON "StripePublication"("mode", "stripeProductId");
CREATE UNIQUE INDEX "StripePublication_mode_stripePriceId_key" ON "StripePublication"("mode", "stripePriceId");
CREATE INDEX "StripePublication_businessId_createdAt_idx" ON "StripePublication"("businessId", "createdAt");

CREATE FUNCTION "protect_stripe_publication_snapshot"() RETURNS trigger AS $$
BEGIN
  IF (NEW."id", NEW."draftId", NEW."businessId", NEW."actorId", NEW."actorSessionVersion", NEW."connectionId", NEW."mode", NEW."stripeAccountId",
      NEW."name", NEW."description", NEW."kind", NEW."amountCents", NEW."currency", NEW."billing",
      NEW."interval", NEW."createdAt")
     IS DISTINCT FROM
     (OLD."id", OLD."draftId", OLD."businessId", OLD."actorId", OLD."actorSessionVersion", OLD."connectionId", OLD."mode", OLD."stripeAccountId",
      OLD."name", OLD."description", OLD."kind", OLD."amountCents", OLD."currency", OLD."billing",
      OLD."interval", OLD."createdAt") THEN
    RAISE EXCEPTION 'Stripe publication snapshots are immutable';
  END IF;
  IF (OLD."stripeProductId" IS NOT NULL AND NEW."stripeProductId" IS DISTINCT FROM OLD."stripeProductId") OR
     (OLD."stripePriceId" IS NOT NULL AND NEW."stripePriceId" IS DISTINCT FROM OLD."stripePriceId") THEN
    RAISE EXCEPTION 'Stripe publication identifiers are immutable';
  END IF;
  IF NEW."status" IS DISTINCT FROM OLD."status" AND NOT (
    (OLD."status" = 'PENDING' AND NEW."status" = 'PRODUCT_CREATING') OR
    (OLD."status" = 'PRODUCT_CREATING' AND NEW."status" = 'PRODUCT_CREATED') OR
    (OLD."status" = 'PRODUCT_CREATED' AND NEW."status" = 'PRICE_CREATING') OR
    (OLD."status" = 'PRICE_CREATING' AND NEW."status" = 'PRICE_CREATED')
  ) THEN
    RAISE EXCEPTION 'Invalid Stripe publication transition';
  END IF;
  IF NEW."status" = OLD."status" AND
     (NEW."operationId", NEW."claimedAt", NEW."stripeProductId", NEW."stripePriceId") IS DISTINCT FROM
     (OLD."operationId", OLD."claimedAt", OLD."stripeProductId", OLD."stripePriceId") THEN
    RAISE EXCEPTION 'Stripe publication state changes require a transition';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "StripePublication_immutable_snapshot"
BEFORE UPDATE ON "StripePublication" FOR EACH ROW EXECUTE FUNCTION "protect_stripe_publication_snapshot"();
