import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type { Store } from "express-rate-limit";
import { z } from "zod";
import type { PrismaClient } from "./generated/prisma/client.js";
import { hashPassword } from "./security.js";

type Delivery = { id: string; payload: string; expiresAt: Date };
type ResetToken = { userId: string; sessionVersion: number };
export type RecoveryMail = { to: string; link: string; language: "en" | "es" };
const payloadSchema = z.object({
  email: z.string().email().max(254),
  token: z.string().regex(/^[a-f0-9]{64}$/),
  language: z.enum(["en", "es"]),
  user: z.object({ id: z.string(), sessionVersion: z.number().int().nonnegative() }).strict().nullable()
}).strict();
const lifetimeMs = 30 * 60 * 1000;

export class PasswordRecovery {
  private readonly key: Buffer;
  private timer?: NodeJS.Timeout;
  private pending?: Promise<void>;
  private stopped = true;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly limits: Store,
    key: string,
    private readonly origin: string,
    private readonly send: (mail: RecoveryMail) => Promise<void>
  ) {
    if (!/^[a-f0-9]{64}$/.test(key)) throw new Error("Invalid password recovery key");
    this.key = Buffer.from(key, "hex");
  }

  private seal(id: string, value: string) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(Buffer.from(id));
    const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]).toString("base64");
  }

  private open(id: string, payload: string) {
    const bytes = Buffer.from(payload, "base64");
    if (bytes.length < 29) throw new Error("Invalid recovery delivery payload");
    const decipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(id));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return payloadSchema.parse(JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8")));
  }

  async request(email: string, language: "en" | "es") {
    const normalizedEmail = email.trim().toLowerCase();
    const addressKey = createHmac("sha256", this.key).update("password-reset:").update(normalizedEmail).digest("hex");
    const count = await this.limits.increment(`reset:${addressKey}`);
    if (count.totalHits > 3) return;
    const id = randomUUID();
    const token = randomBytes(32).toString("hex");
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail }, select: { id: true, sessionVersion: true }
    });
    const payload = this.seal(id, JSON.stringify({ email: normalizedEmail, token, language, user }));
    await this.prisma.passwordResetDelivery.create({
      data: { id, payload, expiresAt: new Date(Date.now() + lifetimeMs) }
    });
  }

  async redeem(token: string, password: string) {
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const newHash = await hashPassword(password);
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<ResetToken[]>`
        UPDATE "PasswordResetToken" SET "usedAt" = CURRENT_TIMESTAMP
        WHERE "tokenHash" = ${tokenHash} AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP
        RETURNING "userId", "sessionVersion"`;
      const reset = rows[0];
      if (!reset) return false;
      const updated = await tx.user.updateMany({
        where: { id: reset.userId, sessionVersion: reset.sessionVersion },
        data: { passwordHash: newHash, sessionVersion: { increment: 1 } }
      });
      if (updated.count !== 1) return false;
      await tx.auditEvent.create({
        data: { actorId: reset.userId, action: "PASSWORD_RESET", targetId: reset.userId }
      });
      return true;
    });
  }

  async processOne() {
    const rows = await this.prisma.$queryRaw<Delivery[]>`
      UPDATE "PasswordResetDelivery" SET "leaseUntil" = CURRENT_TIMESTAMP + INTERVAL '1 minute'
      WHERE "id" = (
        SELECT "id" FROM "PasswordResetDelivery"
        WHERE "expiresAt" > CURRENT_TIMESTAMP AND "nextAttemptAt" <= CURRENT_TIMESTAMP
          AND ("leaseUntil" IS NULL OR "leaseUntil" <= CURRENT_TIMESTAMP)
        ORDER BY "nextAttemptAt", "id" FOR UPDATE SKIP LOCKED LIMIT 1
      ) RETURNING "id", "payload", "expiresAt"`;
    const delivery = rows[0];
    if (!delivery) return false;
    try {
      const data = this.open(delivery.id, delivery.payload);
      const user = data.user && await this.prisma.user.findUnique({ where: { id: data.user.id } });
      if (user && data.user && user.email === data.email && user.sessionVersion === data.user.sessionVersion) {
        const tokenHash = createHash("sha256").update(data.token).digest("hex");
        await this.prisma.passwordResetToken.createMany({
          data: [{
            id: delivery.id, userId: user.id, sessionVersion: data.user.sessionVersion,
            tokenHash, expiresAt: delivery.expiresAt
          }],
          skipDuplicates: true
        });
        const token = await this.prisma.passwordResetToken.findUniqueOrThrow({ where: { id: delivery.id } });
        if (token.tokenHash !== tokenHash || token.userId !== user.id) throw new Error("Recovery token mismatch");
        if (!token.usedAt && token.sessionVersion === user.sessionVersion && token.expiresAt > new Date()) {
          await this.send({ to: user.email, link: `${this.origin}/#reset=${data.token}`, language: data.language });
        }
      }
      await this.prisma.passwordResetDelivery.deleteMany({ where: { id: delivery.id } });
    } catch {
      console.error("Password recovery delivery failed");
      await this.prisma.passwordResetDelivery.updateMany({
        where: { id: delivery.id },
        data: { leaseUntil: null, nextAttemptAt: new Date(Date.now() + 60_000) }
      });
    }
    return true;
  }

  start() {
    if (!this.stopped) return;
    this.stopped = false;
    const tick = () => {
      if (this.pending || this.stopped) return;
      this.pending = (async () => {
        await this.prisma.passwordResetDelivery.deleteMany({ where: { expiresAt: { lte: new Date() } } });
        await this.prisma.passwordResetToken.deleteMany({ where: { expiresAt: { lte: new Date() } } });
        while (!this.stopped && await this.processOne()) {}
      })().catch(() => console.error("Password recovery worker failed")).finally(() => { this.pending = undefined; });
    };
    this.timer = setInterval(tick, 5000);
    this.timer.unref();
    tick();
  }

  async stop() {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.pending;
  }
}
