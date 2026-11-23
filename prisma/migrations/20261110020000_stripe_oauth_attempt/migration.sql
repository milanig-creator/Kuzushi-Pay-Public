CREATE TABLE "StripeOAuthAttempt" (
  "id" TEXT NOT NULL,
  "stateHash" TEXT NOT NULL,
  "sessionHash" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "businessId" TEXT NOT NULL,
  "environment" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "active" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "StripeOAuthAttempt_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "StripeOAuthAttempt_environment_check" CHECK ("environment" = 'SANDBOX'),
  CONSTRAINT "StripeOAuthAttempt_state_hash_check" CHECK ("stateHash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "StripeOAuthAttempt_session_hash_check" CHECK ("sessionHash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "StripeOAuthAttempt_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "StripeOAuthAttempt_businessId_fkey" FOREIGN KEY ("businessId") REFERENCES "Business"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "StripeOAuthAttempt_stateHash_key" ON "StripeOAuthAttempt"("stateHash");
CREATE UNIQUE INDEX "StripeOAuthAttempt_one_active_business" ON "StripeOAuthAttempt"("businessId") WHERE "active" = true;
