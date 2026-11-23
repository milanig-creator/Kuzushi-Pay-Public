import { describe, expect, it, vi } from "vitest";
import { OAuthTokenRotation, type OAuthRotationStore, type RotationClaim } from "./oauth-token-rotation.js";

const secretId = `kp-stripe-oauth-test-${"a".repeat(32)}`;
const stored = {
  access_token: "old_access", refresh_token: "old_refresh", stripe_user_id: "acct_expected", livemode: false
};
const refreshed = { ...stored, access_token: "new_access", refresh_token: "new_refresh" };

function fixture() {
  const claim = (operationId: string): RotationClaim => ({
    connectionId: "connection", businessId: "business", mode: "TEST", accountId: "acct_expected",
    operationId, reference: { secretId, version: "1" }
  });
  const store: OAuthRotationStore = {
    claim: vi.fn(async (_business, _mode, operationId) => claim(operationId)),
    release: vi.fn().mockResolvedValue(true),
    complete: vi.fn().mockResolvedValue(true),
    requireReconnect: vi.fn().mockResolvedValue(true)
  };
  const secrets = {
    accessVersion: vi.fn().mockResolvedValue(Buffer.from(JSON.stringify(stored))),
    addVersion: vi.fn().mockResolvedValue({ secretId, version: "2" })
  };
  const developerKey = vi.fn().mockResolvedValue(Buffer.from("sk_test_fixture"));
  const refresh = vi.fn().mockResolvedValue(refreshed);
  return { store, secrets, developerKey, refresh, service: new OAuthTokenRotation(store, secrets, developerKey, refresh) };
}

describe("OAuth token rotation", () => {
  it("writes the new token pair to a pinned version before returning access", async () => {
    const { service, store, secrets, refresh } = fixture();
    expect(await service.rotate("business", "TEST")).toBe("new_access");
    expect(refresh).toHaveBeenCalledOnce();
    expect(refresh).toHaveBeenCalledWith("sk_test_fixture", "old_refresh");
    expect(secrets.addVersion).toHaveBeenCalledOnce();
    const [target, value] = secrets.addVersion.mock.calls[0];
    expect(target).toBe(secretId);
    expect(JSON.parse(Buffer.from(value).toString())).toEqual(refreshed);
    expect(store.complete).toHaveBeenCalledWith(expect.objectContaining({ reference: { secretId, version: "1" } }), "2");
    expect(store.requireReconnect).not.toHaveBeenCalled();
  });

  it("releases the claim without contacting Stripe when preparation fails", async () => {
    const { service, store, secrets, refresh } = fixture();
    secrets.accessVersion.mockRejectedValueOnce(new Error("sensitive_marker"));
    await expect(service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh preparation failed");
    expect(store.release).toHaveBeenCalledOnce();
    expect(refresh).not.toHaveBeenCalled();
    expect(secrets.addVersion).not.toHaveBeenCalled();
  });

  it("reports an unavailable connection when claim release itself fails", async () => {
    const { service, store, secrets, refresh } = fixture();
    secrets.accessVersion.mockRejectedValueOnce(new Error("sensitive_marker"));
    vi.mocked(store.release).mockRejectedValueOnce(new Error("sensitive_marker"));
    const error = await service.rotate("business", "TEST").catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain("connection remains unavailable");
    expect(String(error)).not.toContain("sensitive_marker");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("never retries an ambiguous Stripe failure and requires reconnect", async () => {
    const { service, store, secrets, refresh } = fixture();
    refresh.mockRejectedValueOnce(new Error("sensitive_marker"));
    await expect(service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh outcome uncertain");
    expect(refresh).toHaveBeenCalledOnce();
    expect(store.requireReconnect).toHaveBeenCalledOnce();
    expect(store.release).not.toHaveBeenCalled();
    expect(secrets.addVersion).not.toHaveBeenCalled();
  });

  it("fails closed when the rotated identity or mode is wrong, or the token was not rotated", async () => {
    for (const response of [
      { ...refreshed, stripe_user_id: "acct_other" },
      { ...refreshed, livemode: true },
      { ...refreshed, refresh_token: "old_refresh" },
      { ...refreshed, refresh_token: "" }
    ]) {
      const { service, store, secrets, refresh } = fixture();
      refresh.mockResolvedValueOnce(response);
      await expect(service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh outcome uncertain");
      expect(store.requireReconnect).toHaveBeenCalledOnce();
      expect(secrets.addVersion).not.toHaveBeenCalled();
    }
  });

  it("does not return tokens if the vault or database outcome is uncertain", async () => {
    const vaultFailure = fixture();
    vaultFailure.secrets.addVersion.mockRejectedValueOnce(new Error("sensitive_marker"));
    await expect(vaultFailure.service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh outcome uncertain");
    expect(vaultFailure.store.requireReconnect).toHaveBeenCalledOnce();
    expect(vaultFailure.store.complete).not.toHaveBeenCalled();

    const changedConnection = fixture();
    vi.mocked(changedConnection.store.complete).mockResolvedValueOnce(false);
    await expect(changedConnection.service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh outcome uncertain");
    expect(changedConnection.store.requireReconnect).toHaveBeenCalledOnce();
  });

  it("does not expose errors when the reconnect state cannot be recorded", async () => {
    const { service, store, refresh } = fixture();
    refresh.mockRejectedValueOnce(new Error("sensitive_marker"));
    vi.mocked(store.requireReconnect).mockRejectedValueOnce(new Error("sensitive_marker"));
    const error = await service.rotate("business", "TEST").catch((failure: unknown) => failure);
    expect(String(error)).toContain("connection remains unavailable");
    expect(String(error)).not.toContain("sensitive_marker");
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("rejects mismatched stored tokens and live developer credentials before Stripe", async () => {
    const { service, secrets, developerKey, refresh, store } = fixture();
    secrets.accessVersion.mockResolvedValueOnce(Buffer.from(JSON.stringify({ ...stored, stripe_user_id: "acct_other" })));
    await expect(service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh preparation failed");
    developerKey.mockResolvedValueOnce(Buffer.from("sk_live_fixture"));
    await expect(service.rotate("business", "TEST")).rejects.toThrow("OAuth refresh preparation failed");
    expect(store.release).toHaveBeenCalledTimes(2);
    expect(refresh).not.toHaveBeenCalled();
  });
});
