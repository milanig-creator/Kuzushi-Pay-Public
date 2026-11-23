CREATE TABLE "StorefrontProposal" (
  "businessId" TEXT NOT NULL,
  "origin" TEXT NOT NULL,
  "returnUrl" TEXT NOT NULL,
  "revision" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "StorefrontProposal_pkey" PRIMARY KEY ("businessId"),
  CONSTRAINT "StorefrontProposal_businessId_fkey" FOREIGN KEY ("businessId")
    REFERENCES "Business"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "StorefrontProposal_length_check" CHECK (
    length("origin") BETWEEN 1 AND 2048 AND length("returnUrl") BETWEEN 1 AND 2048
  )
);
