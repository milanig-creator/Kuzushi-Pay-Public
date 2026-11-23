CREATE TYPE "StripeMode" AS ENUM ('TEST', 'LIVE');
CREATE TYPE "StripeConnectionStatus" AS ENUM ('PENDING_VERIFICATION', 'VERIFIED', 'DISCONNECTED');

CREATE TABLE "StripeConnection" (
  "id" TEXT NOT NULL,
  "businessId" TEXT NOT NULL,
  "mode" "StripeMode" NOT NULL,
  "status" "StripeConnectionStatus" NOT NULL DEFAULT 'PENDING_VERIFICATION',
  "stripeAccountId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "StripeConnection_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "StripeConnection_account_id_format" CHECK ("stripeAccountId" IS NULL OR "stripeAccountId" ~ '^acct_[A-Za-z0-9]+$'),
  CONSTRAINT "StripeConnection_verified_account" CHECK ("status" <> 'VERIFIED' OR "stripeAccountId" IS NOT NULL),
  CONSTRAINT "StripeConnection_businessId_fkey" FOREIGN KEY ("businessId") REFERENCES "Business"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "StripeConnection_businessId_mode_key" ON "StripeConnection"("businessId", "mode");
CREATE UNIQUE INDEX "StripeConnection_mode_stripeAccountId_key" ON "StripeConnection"("mode", "stripeAccountId");

CREATE TABLE "StripeCredentialReference" (
  "connectionId" TEXT NOT NULL,
  "secretId" TEXT NOT NULL,
  "version" TEXT NOT NULL,
  CONSTRAINT "StripeCredentialReference_pkey" PRIMARY KEY ("connectionId"),
  CONSTRAINT "StripeCredentialReference_secret_id_format" CHECK ("secretId" ~ '^kp-stripe-(test|live)-[0-9a-f]{32}$'),
  CONSTRAINT "StripeCredentialReference_version_format" CHECK ("version" ~ '^[1-9][0-9]*$'),
  CONSTRAINT "StripeCredentialReference_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "StripeConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "StripeCredentialReference_secretId_key" ON "StripeCredentialReference"("secretId");
