CREATE TABLE "PasswordResetDelivery" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "payload" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "leaseUntil" TIMESTAMP(3)
);
CREATE INDEX "PasswordResetDelivery_nextAttemptAt_idx" ON "PasswordResetDelivery"("nextAttemptAt");
CREATE INDEX "PasswordResetDelivery_expiresAt_idx" ON "PasswordResetDelivery"("expiresAt");

CREATE TABLE "PasswordResetToken" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "tokenHash" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "sessionVersion" INTEGER NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "PasswordResetToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "PasswordResetToken_tokenHash_key" ON "PasswordResetToken"("tokenHash");
CREATE INDEX "PasswordResetToken_userId_idx" ON "PasswordResetToken"("userId");
CREATE INDEX "PasswordResetToken_expiresAt_idx" ON "PasswordResetToken"("expiresAt");
