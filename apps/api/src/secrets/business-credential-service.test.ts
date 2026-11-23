import { describe, expect, it, vi } from "vitest";
import type { User } from "../repository.js";
import type { SecretManager } from "./secret-manager.js";
import { BusinessCredentialService } from "./business-credential-service.js";

const user: User = { id: "owner-a", email: "owner@example.com", role: "USER", passwordHash: "hash", sessionVersion: 0 };
const ref = { secretId: `kp-stripe-test-${"a".repeat(32)}`, version: "2" };
const session = { userId: user.id, authenticatedAt: Date.now(), authVersion: user.sessionVersion };

function fixture() {
  const repository = {
    findUserById: vi.fn().mockResolvedValue(user),
    findVerifiedTestCredential: vi.fn().mockImplementation(async (_user: User, businessId: string) =>
      businessId === "business-a" ? ref : null)
  };
  const secrets: SecretManager = {
    accessVersion: vi.fn().mockResolvedValue(Buffer.from("harmless-test-value")),
    addVersion: vi.fn(),
    disableVersion: vi.fn()
  };
  const service = new BusinessCredentialService(repository, secrets);
  return { repository, secrets, service };
}

describe("business credential service", () => {
  it("authenticates and resolves a server-owned reference before accessing the vault", async () => {
    const { repository, secrets, service } = fixture();
    expect(Buffer.from(await service.accessTestCredential(session, "business-a")).toString()).toBe("harmless-test-value");
    expect(repository.findVerifiedTestCredential).toHaveBeenCalledWith(user, "business-a");
    expect(secrets.accessVersion).toHaveBeenCalledWith(ref);
  });

  it("does not access another business or disclose its reference", async () => {
    const { secrets, service } = fixture();
    await expect(service.accessTestCredential(session, "business-b")).rejects.toThrow("Credential unavailable");
    expect(secrets.accessVersion).not.toHaveBeenCalled();
  });

  it("rejects missing, expired, future and deleted-user sessions before looking up credentials", async () => {
    const { repository, secrets, service } = fixture();
    for (const data of [{}, { ...session, authenticatedAt: Date.now() - 8 * 60 * 60 * 1000 },
      { ...session, authenticatedAt: Date.now() + 60000 }]) {
      await expect(service.accessTestCredential(data, "business-a")).rejects.toThrow("Credential unavailable");
    }
    repository.findUserById.mockResolvedValueOnce(null);
    await expect(service.accessTestCredential(session, "business-a")).rejects.toThrow("Credential unavailable");
    expect(repository.findVerifiedTestCredential).not.toHaveBeenCalled();
    expect(secrets.accessVersion).not.toHaveBeenCalled();
  });

  it("rejects malformed, unpinned and live-mode references before vault access", async () => {
    const { repository, secrets, service } = fixture();
    for (const invalid of [
      { secretId: `kp-stripe-live-${"a".repeat(32)}`, version: "1" },
      { secretId: "rk_test_not-a-reference", version: "1" },
      { ...ref, version: "latest" }
    ]) {
      repository.findVerifiedTestCredential.mockResolvedValueOnce(invalid);
      await expect(service.accessTestCredential(session, "business-a")).rejects.toThrow("Credential unavailable");
    }
    expect(secrets.accessVersion).not.toHaveBeenCalled();
  });
});
