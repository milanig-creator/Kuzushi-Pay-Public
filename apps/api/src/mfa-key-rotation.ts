import type { PrismaClient } from "./generated/prisma/client.js";
import { MfaCrypto } from "./mfa-crypto.js";

export async function rotateMfaKey(prisma: PrismaClient, oldKey: string, newKey: string) {
  const oldCrypto = new MfaCrypto(oldKey);
  const newCrypto = new MfaCrypto(newKey);
  if (oldCrypto.fingerprint === newCrypto.fingerprint) throw new Error("New MFA key must be different");
  return prisma.$transaction(async (tx) => {
    const state = await tx.$queryRaw<{ fingerprint: string }[]>`
      SELECT "fingerprint" FROM "MfaKeyState" WHERE "id" = 'primary' FOR UPDATE`;
    if (state[0]?.fingerprint !== oldCrypto.fingerprint) throw new Error("Current MFA key does not match the database");
    let cursor: string | undefined;
    let count = 0;
    for (;;) {
      const batch = await tx.mfaAuthenticator.findMany({
        take: 100, orderBy: { userId: "asc" },
        ...(cursor ? { cursor: { userId: cursor }, skip: 1 } : {})
      });
      if (batch.length === 0) break;
      for (const factor of batch) {
        const secret = oldCrypto.open(factor.userId, factor.secret);
        await tx.mfaAuthenticator.update({
          where: { userId: factor.userId }, data: { secret: newCrypto.seal(factor.userId, secret) }
        });
      }
      count += batch.length;
      cursor = batch[batch.length - 1].userId;
    }
    await tx.$executeRaw`DELETE FROM "session" WHERE "sess"::jsonb ? 'mfaPending'`;
    await tx.mfaKeyState.update({ where: { id: "primary" }, data: { fingerprint: newCrypto.fingerprint } });
    const audit = await tx.auditEvent.create({ data: { action: "MFA_KEY_ROTATED" }, select: { id: true } });
    return { count, auditId: audit.id };
  }, { timeout: 300_000 });
}
