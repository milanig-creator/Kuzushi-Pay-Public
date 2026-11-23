import { describe, expect, it, vi } from "vitest";
import { SandboxOAuthService, validateSandboxOAuthConfig } from "./oauth-sandbox.js";

const config = {
  installUrl: "https://marketplace.stripe.com/oauth/v2/authorize?client_id=client_test_example",
  redirectUri: "https://test.example.com/api/stripe/oauth/sandbox/callback"
};
const externalConfig = {
  ...config,
  installUrl: `https://marketplace.stripe.com/oauth/v2/${"a".repeat(40)}/authorize?client_id=client_test_example&redirect_uri=${encodeURIComponent(config.redirectUri)}`
};
const user = { id: "user", email: "owner@example.com", role: "USER" as const, passwordHash: "fixture", sessionVersion: 0 };
const auth = { userId: user.id, authenticatedAt: Date.now(), authVersion: user.sessionVersion };

describe("sandbox OAuth", () => {
  it("accepts the observed external test link and rejects unsafe authorization URLs", () => {
    for (const invalid of [
      { ...config, installUrl: "https://evil.example/oauth/v2/authorize?client_id=x" },
      { ...config, installUrl: `${config.installUrl}&state=attacker` },
      { ...config, installUrl: `${config.installUrl}&client_id=second` },
      { ...externalConfig, installUrl: externalConfig.installUrl.replace("a".repeat(40), "a".repeat(39)) },
      { ...externalConfig, installUrl: externalConfig.installUrl.replace("a".repeat(40), "../other") },
      { ...externalConfig, installUrl: `${externalConfig.installUrl}&redirect_uri=${encodeURIComponent(config.redirectUri)}` },
      { ...externalConfig, installUrl: externalConfig.installUrl.replace(encodeURIComponent(config.redirectUri), encodeURIComponent("https://evil.example/callback")) },
      { ...externalConfig, installUrl: `${externalConfig.installUrl}&state=attacker` },
      { ...config, redirectUri: "http://test.example.com/api/stripe/oauth/sandbox/callback" },
      { ...config, redirectUri: `${config.redirectUri}?code=not-allowed` }
    ]) expect(() => validateSandboxOAuthConfig(invalid)).toThrow();
    expect(() => validateSandboxOAuthConfig(config)).not.toThrow();
    expect(() => validateSandboxOAuthConfig(externalConfig)).not.toThrow();
  });

  it("generates session-bound state for an external link with a preconfigured callback", async () => {
    const repository = {
      findUserById: vi.fn().mockResolvedValue(user),
      findBusiness: vi.fn().mockResolvedValue({ id: "business", name: "Test" })
    };
    const attempts = { create: vi.fn().mockResolvedValue(true), consume: vi.fn() };
    const service = new SandboxOAuthService(repository, attempts, externalConfig, "test-secret");
    const result = await service.initiate(auth, "session", "business");
    if ("error" in result) throw new Error(result.error);
    const url = new URL(result.url);
    expect(url.pathname).toBe(`/oauth/v2/${"a".repeat(40)}/authorize`);
    expect(url.searchParams.getAll("redirect_uri")).toEqual([config.redirectUri]);
    expect(url.searchParams.getAll("state")).toHaveLength(1);
    expect(url.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(attempts.create).toHaveBeenCalledOnce();
  });

  it("limits the exposed sandbox action to its configured test business", () => {
    const repository = { findUserById: vi.fn(), findBusiness: vi.fn() };
    const attempts = { create: vi.fn(), consume: vi.fn() };
    const scoped = new SandboxOAuthService(repository, attempts, { ...config, businessId: "test-business" }, "test-secret");
    const unscoped = new SandboxOAuthService(repository, attempts, config, "test-secret");
    expect(scoped.isEnabledForBusiness("test-business")).toBe(true);
    expect(scoped.isEnabledForBusiness("other-business")).toBe(false);
    expect(unscoped.isEnabledForBusiness("any-business")).toBe(true);
  });

  it("rejects invalid and expired sessions before creating an attempt", async () => {
    const repository = { findUserById: vi.fn().mockResolvedValue(user), findBusiness: vi.fn() };
    const attempts = { create: vi.fn(), consume: vi.fn() };
    const service = new SandboxOAuthService(repository, attempts, config, "test-secret");
    for (const session of [{}, { ...auth, authenticatedAt: Date.now() - 9 * 60 * 60 * 1000 }]) {
      expect(await service.initiate(session, "session", "business")).toEqual({ error: "UNAUTHENTICATED" });
      expect(await service.callback(session, "session", "a".repeat(43))).toBe(false);
    }
    expect(attempts.create).not.toHaveBeenCalled();
    expect(attempts.consume).not.toHaveBeenCalled();
  });
});
