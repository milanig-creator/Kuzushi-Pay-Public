import type { Options, Store } from "express-rate-limit";
import type { PrismaClient } from "./generated/prisma/client.js";

type RateLimitRow = { totalHits: number; resetTime: Date };

export class PostgresRateLimitStore implements Store {
  readonly localKeys = false;
  private windowMs = 15 * 60 * 1000;
  private cleanupTimer?: NodeJS.Timeout;

  constructor(private readonly prisma: PrismaClient) {}

  init(options: Options) {
    this.windowMs = options.windowMs;
    this.shutdown();
    this.cleanupTimer = setInterval(() => {
      void this.prisma.loginRateLimit.deleteMany({ where: { resetTime: { lte: new Date() } } })
        .catch(() => console.error("Login rate-limit cleanup failed"));
    }, Math.min(this.windowMs, 60_000));
    this.cleanupTimer.unref();
  }

  async get(key: string) {
    const row = await this.prisma.loginRateLimit.findUnique({
      where: { key }, select: { totalHits: true, resetTime: true }
    });
    return row && row.resetTime > new Date()
      ? { totalHits: row.totalHits, resetTime: row.resetTime }
      : undefined;
  }

  async increment(key: string) {
    const rows = await this.prisma.$queryRaw<RateLimitRow[]>`
      INSERT INTO "LoginRateLimit" ("key", "totalHits", "resetTime")
      VALUES (${key}, 1, CURRENT_TIMESTAMP + (${this.windowMs}::double precision * INTERVAL '1 millisecond'))
      ON CONFLICT ("key") DO UPDATE SET
        "totalHits" = CASE
          WHEN "LoginRateLimit"."resetTime" <= CURRENT_TIMESTAMP THEN 1
          ELSE "LoginRateLimit"."totalHits" + 1
        END,
        "resetTime" = CASE
          WHEN "LoginRateLimit"."resetTime" <= CURRENT_TIMESTAMP THEN EXCLUDED."resetTime"
          ELSE "LoginRateLimit"."resetTime"
        END
      RETURNING "totalHits", "resetTime"`;
    const row = rows[0];
    if (!row) throw new Error("Login rate-limit counter was not returned");
    return { totalHits: row.totalHits, resetTime: row.resetTime };
  }

  async decrement(key: string) {
    await this.prisma.$executeRaw`
      UPDATE "LoginRateLimit"
      SET "totalHits" = "totalHits" - 1
      WHERE "key" = ${key} AND "totalHits" > 0 AND "resetTime" > CURRENT_TIMESTAMP`;
  }

  async resetKey(key: string) {
    await this.prisma.loginRateLimit.deleteMany({ where: { key } });
  }

  async resetAll() {
    await this.prisma.loginRateLimit.deleteMany();
  }

  shutdown() {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.cleanupTimer = undefined;
  }
}
