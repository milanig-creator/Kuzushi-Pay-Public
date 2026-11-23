import { createHash, randomBytes } from "node:crypto";
import type { Store } from "express-rate-limit";
import type { Prisma, PrismaClient } from "./generated/prisma/client.js";
import { backupCodeHash, newAuthenticator, newBackupCodes, verifyAuthenticator } from "./mfa-factors.js";
import { MfaCrypto } from "./mfa-crypto.js";

export class MfaRateLimitError extends Error {
  constructor() { super("MFA attempt limit exceeded"); }
}

export class MfaStore {
  private readonly crypto: MfaCrypto;

  constructor(
    private readonly prisma: PrismaClient,
    key: string,
    private readonly limits: Store,
    private readonly clock: () => number = Date.now
  ) {
    this.crypto = new MfaCrypto(key);
  }

  async initialize() {
    await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(485723105)`;
      const state = await tx.mfaKeyState.findUnique({ where: { id: "primary" } });
      if (state) {
        await this.crypto.requireCurrent(tx);
      } else {
        if (await tx.mfaAuthenticator.count() !== 0) throw new Error("MFA key state is missing for existing authenticators");
        await tx.mfaKeyState.create({ data: { id: "primary", fingerprint: this.crypto.fingerprint } });
      }
    });
  }

  get keyFingerprint() {
    return this.crypto.fingerprint;
  }

  private async beginAttempt(userId: string, sessionVersion: number) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, sessionVersion }, select: { id: true }
    });
    if (!user) return false;
    const key = this.crypto.rateKey(userId);
    const count = await this.limits.increment(`mfa:${key}`);
    if (count.totalHits > 10) throw new MfaRateLimitError();
    return true;
  }

  prepareEnrollment(userId: string, email: string) {
    const authenticator = newAuthenticator(email);
    // Keep pendingSecret in the server-side enrollment session, not in client input.
    return { ...authenticator, pendingSecret: this.crypto.seal(userId, authenticator.secret) };
  }

  async isEnrolled(userId: string) {
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      return !!await tx.mfaAuthenticator.findUnique({ where: { userId }, select: { userId: true } });
    });
  }

  async requiresRecovery(userId: string) {
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      return !!await tx.mfaRecoveryGrant.findUnique({ where: { userId }, select: { userId: true } });
    });
  }

  async recoveryProofValid(userId: string, proof: string | undefined) {
    if (!proof) return false;
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      const grant = await tx.mfaRecoveryGrant.findUnique({ where: { userId } });
      return !!grant && grant.codeHash === proof && grant.expiresAt.getTime() > this.clock();
    });
  }

  private async lockActor(tx: Prisma.TransactionClient, userId: string, version: number) {
    const users = await tx.$queryRaw<{ id: string }[]>`
      SELECT "id" FROM "User" WHERE "id" = ${userId} AND "sessionVersion" = ${version} FOR UPDATE`;
    return !!users[0];
  }

  private async saveBackupCodes(tx: Prisma.TransactionClient, userId: string) {
    const codes = newBackupCodes();
    const hashes = codes.map((code) => {
      const codeHash = backupCodeHash(code);
      if (!codeHash) throw new Error("Invalid generated backup code");
      return { userId, codeHash };
    });
    await tx.mfaBackupCode.createMany({ data: hashes });
    return codes;
  }

  private async consume(tx: Prisma.TransactionClient, userId: string, code: string) {
    const factor = await tx.mfaAuthenticator.findUnique({ where: { userId } });
    if (!factor) return false;
    const hash = backupCodeHash(code);
    if (hash) {
      const deleted = await tx.mfaBackupCode.deleteMany({ where: { userId, codeHash: hash } });
      return deleted.count === 1;
    }
    const step = await verifyAuthenticator(this.crypto.open(userId, factor.secret), code, this.clock(), factor.lastTimeStep);
    if (step === null) return false;
    await tx.mfaAuthenticator.update({ where: { userId }, data: { lastTimeStep: step } });
    return true;
  }

  async enroll(userId: string, sessionVersion: number, pendingSecret: string, token: string, recoveryProof?: string) {
    if (!await this.beginAttempt(userId, sessionVersion)) return null;
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      if (!await this.lockActor(tx, userId, sessionVersion) ||
          await tx.mfaAuthenticator.findUnique({ where: { userId } })) return null;
      const grant = await tx.mfaRecoveryGrant.findUnique({ where: { userId } });
      if (grant && (grant.codeHash !== recoveryProof || grant.expiresAt.getTime() <= this.clock())) return null;
      if (!grant && recoveryProof) return null;
      const secret = this.crypto.open(userId, pendingSecret);
      const step = await verifyAuthenticator(secret, token, this.clock(), null);
      if (step === null) {
        await tx.auditEvent.create({ data: { actorId: userId, targetId: userId, action: "MFA_ENROLLMENT_FAILED" } });
        return null;
      }
      await tx.mfaAuthenticator.create({ data: { userId, secret: pendingSecret, lastTimeStep: step } });
      if (grant) await tx.mfaRecoveryGrant.delete({ where: { userId } });
      const codes = await this.saveBackupCodes(tx, userId);
      await tx.user.update({ where: { id: userId }, data: { sessionVersion: { increment: 1 } } });
      await tx.auditEvent.create({ data: { actorId: userId, targetId: userId, action: "MFA_ENROLLED" } });
      return { backupCodes: codes, sessionVersion: sessionVersion + 1 };
    });
  }

  async verifyRecoveryCode(userId: string, sessionVersion: number, code: string) {
    if (!await this.beginAttempt(userId, sessionVersion)) return null;
    const codeHash = createHash("sha256").update(code).digest("hex");
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      if (!await this.lockActor(tx, userId, sessionVersion)) return null;
      const grant = await tx.mfaRecoveryGrant.findUnique({ where: { userId } });
      const valid = grant && grant.codeHash === codeHash && grant.expiresAt.getTime() > this.clock();
      await tx.auditEvent.create({
        data: { actorId: userId, targetId: userId, action: valid ? "MFA_RECOVERY_CODE_VERIFIED" : "MFA_RECOVERY_CODE_FAILED" }
      });
      return valid ? codeHash : null;
    });
  }

  async issueRecovery(actorId: string, sessionVersion: number, targetEmail: string, code: string) {
    if (!await this.beginAttempt(actorId, sessionVersion)) return { status: "unauthenticated" } as const;
    const recoveryCode = randomBytes(32).toString("hex");
    const codeHash = createHash("sha256").update(recoveryCode).digest("hex");
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      const users = await tx.$queryRaw<{ id: string; email: string; role: "ADMIN" | "USER"; sessionVersion: number }[]>`
        SELECT "id", "email", "role", "sessionVersion" FROM "User"
        WHERE "id" = ${actorId} OR "email" = ${targetEmail} ORDER BY "id" FOR UPDATE`;
      const actor = users.find((user) => user.id === actorId);
      const target = users.find((user) => user.email === targetEmail);
      if (!actor || actor.role !== "ADMIN" || actor.sessionVersion !== sessionVersion) {
        return { status: "unauthenticated" } as const;
      }
      if (!target || target.id === actor.id || target.role !== "USER" ||
          (!await tx.mfaAuthenticator.findUnique({ where: { userId: target.id } }) &&
           !await tx.mfaRecoveryGrant.findUnique({ where: { userId: target.id } }))) {
        return { status: "invalid_target" } as const;
      }
      if (!await this.consume(tx, actor.id, code)) {
        await tx.auditEvent.create({ data: { actorId, targetId: target.id, action: "MFA_RECOVERY_ISSUE_FAILED" } });
        return { status: "invalid_mfa" } as const;
      }
      await tx.mfaAuthenticator.deleteMany({ where: { userId: target.id } });
      await tx.mfaBackupCode.deleteMany({ where: { userId: target.id } });
      const expiresAt = new Date(this.clock() + 30 * 60 * 1000);
      await tx.mfaRecoveryGrant.upsert({
        where: { userId: target.id }, create: { userId: target.id, codeHash, expiresAt },
        update: { codeHash, expiresAt }
      });
      await tx.user.update({ where: { id: target.id }, data: { sessionVersion: { increment: 1 } } });
      await tx.auditEvent.create({ data: { actorId, targetId: target.id, action: "MFA_RECOVERY_ISSUED" } });
      return { status: "issued", recoveryCode } as const;
    });
  }

  async verify(userId: string, sessionVersion: number, code: string) {
    if (!await this.beginAttempt(userId, sessionVersion)) return false;
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      if (!await this.lockActor(tx, userId, sessionVersion)) return false;
      if (!await this.consume(tx, userId, code)) {
        await tx.auditEvent.create({ data: { actorId: userId, targetId: userId, action: "MFA_CHALLENGE_FAILED" } });
        return false;
      }
      await tx.auditEvent.create({ data: { actorId: userId, targetId: userId, action: "MFA_CHALLENGE_SUCCEEDED" } });
      return true;
    });
  }

  async replaceBackupCodes(userId: string, sessionVersion: number, code: string) {
    if (!await this.beginAttempt(userId, sessionVersion)) return null;
    return this.prisma.$transaction(async (tx) => {
      await this.crypto.requireCurrent(tx);
      if (!await this.lockActor(tx, userId, sessionVersion)) return null;
      if (!await this.consume(tx, userId, code)) {
        await tx.auditEvent.create({ data: { actorId: userId, targetId: userId, action: "MFA_BACKUP_CODES_REPLACEMENT_FAILED" } });
        return null;
      }
      await tx.mfaBackupCode.deleteMany({ where: { userId } });
      const codes = await this.saveBackupCodes(tx, userId);
      await tx.auditEvent.create({ data: { actorId: userId, targetId: userId, action: "MFA_BACKUP_CODES_REPLACED" } });
      return codes;
    });
  }
}
