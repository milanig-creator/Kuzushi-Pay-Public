import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { Prisma } from "./generated/prisma/client.js";

export class MfaCrypto {
  private readonly key: Buffer;
  readonly fingerprint: string;

  constructor(key: string) {
    if (!/^[a-f0-9]{64}$/.test(key) || /^0+$/.test(key)) throw new Error("Invalid MFA encryption key");
    this.key = Buffer.from(key, "hex");
    this.fingerprint = createHmac("sha256", this.key).update("kuzushi-mfa-key-check").digest("hex");
  }

  rateKey(userId: string) {
    return createHmac("sha256", this.key).update("mfa-attempts:").update(userId).digest("hex");
  }

  seal(userId: string, secret: string) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(Buffer.from(userId));
    const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
    return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]).toString("base64");
  }

  open(userId: string, payload: string) {
    const bytes = Buffer.from(payload, "base64");
    if (bytes.length < 29) throw new Error("Invalid MFA authenticator payload");
    const decipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(userId));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8");
  }

  async requireCurrent(tx: Prisma.TransactionClient) {
    const rows = await tx.$queryRaw<{ fingerprint: string }[]>`
      SELECT "fingerprint" FROM "MfaKeyState" WHERE "id" = 'primary' FOR SHARE`;
    if (rows[0]?.fingerprint !== this.fingerprint) throw new Error("MFA encryption key does not match the database");
  }
}
