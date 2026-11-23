CREATE TABLE "MfaAuthenticator" (
  "userId" TEXT NOT NULL PRIMARY KEY,
  "secret" TEXT NOT NULL,
  "lastTimeStep" INTEGER NOT NULL,
  CONSTRAINT "MfaAuthenticator_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "MfaBackupCode" (
  "userId" TEXT NOT NULL,
  "codeHash" TEXT NOT NULL,
  CONSTRAINT "MfaBackupCode_pkey" PRIMARY KEY ("userId", "codeHash"),
  CONSTRAINT "MfaBackupCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
