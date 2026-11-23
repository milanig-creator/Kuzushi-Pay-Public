ALTER TABLE "StripeOAuthAttempt" DROP CONSTRAINT "StripeOAuthAttempt_environment_check";
ALTER TABLE "StripeOAuthAttempt" ADD CONSTRAINT "StripeOAuthAttempt_environment_check"
  CHECK ("environment" IN ('SANDBOX', 'LIVE'));
DROP INDEX "StripeOAuthAttempt_one_active_business";
CREATE UNIQUE INDEX "StripeOAuthAttempt_one_active_business"
  ON "StripeOAuthAttempt" ("businessId", "environment") WHERE "active" = true;
