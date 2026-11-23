ALTER TABLE "CheckoutOrder" ADD COLUMN "storefrontRequestId" TEXT;
CREATE UNIQUE INDEX "CheckoutOrder_publicationId_storefrontRequestId_key"
  ON "CheckoutOrder" ("publicationId", "storefrontRequestId");
