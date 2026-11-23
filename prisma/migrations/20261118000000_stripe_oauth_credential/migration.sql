CREATE TYPE "StripeOAuthCredentialStatus" AS ENUM ('READY', 'REFRESHING', 'RECONNECT_REQUIRED');

CREATE TABLE "StripeOAuthCredential" (
  "connectionId" TEXT NOT NULL,
  "secretId" TEXT NOT NULL,
  "version" TEXT NOT NULL,
  "status" "StripeOAuthCredentialStatus" NOT NULL DEFAULT 'READY',
  "operationId" TEXT,
  CONSTRAINT "StripeOAuthCredential_pkey" PRIMARY KEY ("connectionId"),
  CONSTRAINT "StripeOAuthCredential_secret_id_format" CHECK ("secretId" ~ '^kp-stripe-oauth-(test|live)-[0-9a-f]{32}$'),
  CONSTRAINT "StripeOAuthCredential_version_format" CHECK ("version" ~ '^[1-9][0-9]*$'),
  CONSTRAINT "StripeOAuthCredential_operation_check" CHECK (
    ("status" = 'REFRESHING' AND "operationId" IS NOT NULL AND "operationId" ~ '^[0-9a-f]{32}$')
    OR ("status" <> 'REFRESHING' AND "operationId" IS NULL)
  ),
  CONSTRAINT "StripeOAuthCredential_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "StripeConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "StripeOAuthCredential_secretId_key" ON "StripeOAuthCredential"("secretId");
