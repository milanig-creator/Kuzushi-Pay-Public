import { afterEach, describe, expect, it, vi } from "vitest";
import { scryptSync } from "node:crypto";
import { hashPassword, passwordNeedsUpgrade, PasswordWorkLimitError, verifyPassword } from "./security.js";
import { loadConfig } from "./config.js";

afterEach(() => vi.unstubAllEnvs());

describe("password storage", () => {
  it("uses unique salts and verifies correct and incorrect passwords", async () => {
    const first = await hashPassword("test-password-with-length");
    const second = await hashPassword("test-password-with-length");
    expect(first).toMatch(/^scrypt-v2:[0-9a-f]{32}:[0-9a-f]{128}$/);
    expect(first).not.toEqual(second);
    expect(await verifyPassword("test-password-with-length", first)).toBe(true);
    expect(await verifyPassword("wrong", first)).toBe(false);
    expect(passwordNeedsUpgrade(first)).toBe(false);
  }, 30000);

  it("recognizes legacy hashes and rejects malformed formats", async () => {
    const salt = "01".repeat(16);
    const legacy = `scrypt:${salt}:${scryptSync("old-password", salt, 64).toString("hex")}`;
    expect(passwordNeedsUpgrade(legacy)).toBe(true);
    expect(await verifyPassword("old-password", legacy)).toBe(true);
    expect(await verifyPassword("wrong", legacy)).toBe(false);
    await expect(verifyPassword("old-password", `${legacy}:extra`)).rejects.toThrow("Invalid password hash");
  }, 30000);

  it("bounds concurrent password work and releases capacity afterward", async () => {
    const ongoing = Array.from({ length: 4 }, () => hashPassword("test-password-with-length"));
    await expect(hashPassword("test-password-with-length")).rejects.toBeInstanceOf(PasswordWorkLimitError);
    await expect(verifyPassword("test-password-with-length", `scrypt-v2:${"00".repeat(16)}:${"00".repeat(64)}`))
      .rejects.toBeInstanceOf(PasswordWorkLimitError);
    await Promise.all(ongoing);
    const next = await hashPassword("test-password-with-length");
    expect(await verifyPassword("test-password-with-length", next)).toBe(true);
  }, 30000);
});

describe("configuration", () => {
  it("rejects placeholder secrets and insecure production origins", () => {
    vi.stubEnv("DATABASE_URL", "postgresql://test:test@localhost:5432/test");
    vi.stubEnv("SESSION_SECRET", "REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS");
    vi.stubEnv("APP_ORIGIN", "https://pay.example.com");
    vi.stubEnv("NODE_ENV", "production");
    expect(() => loadConfig()).toThrow();
    vi.stubEnv("SESSION_SECRET", "a-unique-test-secret-over-32-characters");
    vi.stubEnv("APP_ORIGIN", "http://pay.example.com");
    expect(() => loadConfig()).toThrow();
    vi.stubEnv("APP_ORIGIN", "https://pay.example.com/path");
    expect(() => loadConfig()).toThrow();
    vi.stubEnv("APP_ORIGIN", "https://pay.example.com");
    expect(loadConfig().NODE_ENV).toBe("production");
  });
});
