import { randomBytes, scrypt as callbackScrypt, timingSafeEqual } from "node:crypto";
const currentParameters = { N: 2 ** 15, r: 8, p: 3, maxmem: 64 * 1024 * 1024 };
const maxConcurrentDerivations = 4;
let activeDerivations = 0;

export class PasswordWorkLimitError extends Error {
  constructor() { super("Password hashing capacity exhausted"); }
}

async function derive(password: string, salt: string, legacy: boolean): Promise<Buffer> {
  if (activeDerivations >= maxConcurrentDerivations) throw new PasswordWorkLimitError();
  activeDerivations++;
  try {
    return await new Promise((resolve, reject) => {
      callbackScrypt(password, salt, 64, legacy ? {} : currentParameters, (error, derived) => {
        if (error) reject(error);
        else resolve(derived);
      });
    });
  } finally {
    activeDerivations--;
  }
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const hash = await derive(password, salt, false);
  return `scrypt-v2:${salt}:${hash.toString("hex")}`;
}

export function passwordNeedsUpgrade(stored: string): boolean {
  return stored.startsWith("scrypt:");
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(":");
  const [algorithm, salt, hash] = parts;
  if (parts.length !== 3 || !["scrypt", "scrypt-v2"].includes(algorithm) ||
      !/^[0-9a-f]{32}$/.test(salt ?? "") || !/^[0-9a-f]{128}$/.test(hash ?? "")) {
    throw new Error("Invalid password hash");
  }
  const expected = Buffer.from(hash, "hex");
  const actual = await derive(password, salt, algorithm === "scrypt");
  return timingSafeEqual(expected, actual);
}
