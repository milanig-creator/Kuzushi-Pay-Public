CREATE TABLE "LoginRateLimit" (
  "key" TEXT NOT NULL,
  "totalHits" INTEGER NOT NULL,
  "resetTime" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "LoginRateLimit_pkey" PRIMARY KEY ("key"),
  CONSTRAINT "LoginRateLimit_totalHits_check" CHECK ("totalHits" >= 0)
);
CREATE INDEX "LoginRateLimit_resetTime_idx" ON "LoginRateLimit"("resetTime");
