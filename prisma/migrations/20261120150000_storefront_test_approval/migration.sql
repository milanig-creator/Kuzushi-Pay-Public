ALTER TABLE "StorefrontProposal" ADD COLUMN "testApprovedAt" TIMESTAMP(3);
ALTER TABLE "CheckoutOrder" ADD COLUMN "storefrontRevision" TEXT;
