import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { loadLiveOAuthClient } from "./live-oauth-client.js";
import { encodeStripeOAuthTokens } from "./oauth-sandbox-exchange.js";

const businessId = "review-business";
const accountId = "acct_Review";
const secretId = `kp-stripe-oauth-live-${createHash("sha256").update(businessId).digest("hex").slice(0, 32)}`;
const reference = { secretId, version: "1" };
const binding = { accountId, connectionId: "review-connection", reference };
const tokens = {
  accountId, livemode: true, accessToken: "oauth_fixture", refreshToken: "refresh_fixture",
  publishableKey: "pk_live_ExampleKey123"
};

function fixture() {
  const find = vi.fn().mockResolvedValue(binding);
  const secrets = { accessVersion: vi.fn().mockResolvedValue(encodeStripeOAuthTokens(tokens, Date.now())) };
  const rotation = { rotate: vi.fn().mockResolvedValue("rotated_fixture") };
  return { find, secrets, rotation, load: () => loadLiveOAuthClient(businessId, accountId, find, secrets, rotation) };
}

describe("live Stripe OAuth client", () => {
  it("uses a fresh credential from the pinned version", async () => {
    const { find, secrets, rotation, load } = fixture();
    await expect(load()).resolves.toMatchObject({
      accountId, connectionId: binding.connectionId, publishableKey: tokens.publishableKey
    });
    expect(secrets.accessVersion).toHaveBeenCalledExactlyOnceWith(reference);
    expect(find).toHaveBeenCalledTimes(2);
    expect(rotation.rotate).not.toHaveBeenCalled();
  });

  it("rotates legacy credentials and uses the newly pinned version", async () => {
    const { find, secrets, rotation, load } = fixture();
    const next = { ...reference, version: "2" };
    find.mockResolvedValueOnce(binding).mockResolvedValue({ ...binding, reference: next });
    secrets.accessVersion.mockResolvedValueOnce(encodeStripeOAuthTokens({ ...tokens, publishableKey: undefined }));
    await expect(load()).resolves.toMatchObject({ accountId, publishableKey: tokens.publishableKey });
    expect(rotation.rotate).toHaveBeenCalledExactlyOnceWith(businessId, "LIVE", reference);
    expect(secrets.accessVersion).toHaveBeenLastCalledWith(next);
  });

  it("rejects cross-account and changed credentials before returning a client", async () => {
    const { find, secrets, rotation, load } = fixture();
    secrets.accessVersion.mockResolvedValueOnce(encodeStripeOAuthTokens({ ...tokens, accountId: "acct_Other" }, Date.now()));
    await expect(load()).rejects.toThrow("binding mismatch");
    find.mockResolvedValueOnce(binding).mockResolvedValueOnce(null);
    await expect(load()).rejects.toThrow("credential changed");
    expect(rotation.rotate).not.toHaveBeenCalled();
  });
});
