import { describe, expect, it } from "vitest";
import { backupCodeHash, newAuthenticator, newBackupCodes, verifyAuthenticator } from "./mfa-factors.js";

describe("MFA factors", () => {
  it("verifies standard TOTP values within the clock window and rejects replay", async () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    expect(await verifyAuthenticator(secret, "287082", 59_000, null)).toBe(1);
    expect(await verifyAuthenticator(secret, "287082", 89_000, null)).toBe(1);
    expect(await verifyAuthenticator(secret, "287082", 89_000, 1)).toBeNull();
    expect(await verifyAuthenticator(secret, "287082", 120_000, null)).toBeNull();
    expect(await verifyAuthenticator(secret, "not-a-code", 59_000, null)).toBeNull();
  });

  it("generates distinct authenticator secrets and compatible provisioning URIs", () => {
    const first = newAuthenticator("owner@example.com");
    const second = newAuthenticator("owner@example.com");
    expect(first.secret).not.toEqual(second.secret);
    const uri = new URL(first.uri);
    expect(uri.protocol).toBe("otpauth:");
    expect(uri.searchParams.get("secret")).toBe(first.secret);
    expect(uri.searchParams.get("issuer")).toBe("Kuzushi Pay");
  });

  it("generates distinct backup codes that can be hashed case-insensitively", () => {
    const codes = newBackupCodes();
    expect(new Set(codes).size).toBe(codes.length);
    const hash = backupCodeHash(codes[0]);
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(backupCodeHash(codes[0].toUpperCase())).toBe(hash);
    expect(backupCodeHash("invalid")).toBeNull();
  });
});
