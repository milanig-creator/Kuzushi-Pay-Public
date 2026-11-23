import { createHash, randomBytes } from "node:crypto";
import { generateSecret, generateURI, verify } from "otplib";

export function newAuthenticator(email: string) {
  const secret = generateSecret();
  return {
    secret,
    uri: generateURI({ issuer: "Kuzushi Pay", label: email, secret })
  };
}

export async function verifyAuthenticator(secret: string, token: string, now: number, lastTimeStep: number | null) {
  if (!/^[0-9]{6}$/.test(token)) return null;
  const result = await verify({ secret, token, epoch: Math.floor(now / 1000), epochTolerance: 30 });
  if (!result.valid || !("timeStep" in result)) return null;
  // The caller must atomically check and advance the stored time step.
  return lastTimeStep === null || result.timeStep > lastTimeStep ? result.timeStep : null;
}

export function newBackupCodes() {
  return Array.from({ length: 10 }, () => {
    const raw = randomBytes(16).toString("hex");
    return [raw.slice(0, 8), raw.slice(8, 16), raw.slice(16, 24), raw.slice(24)].join("-");
  });
}

export function backupCodeHash(code: string) {
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{8}){3}$/i.test(code)) return null;
  return createHash("sha256").update(code.replaceAll("-", "").toLowerCase()).digest("hex");
}
