CREATE TABLE "MfaRecoveryGrant" (
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MfaRecoveryGrant_pkey" PRIMARY KEY ("userId")
);

ALTER TABLE "MfaRecoveryGrant" ADD CONSTRAINT "MfaRecoveryGrant_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
