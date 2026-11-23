import { describe, expect, it, vi } from "vitest";
import {
  exchangeWithStripe, parseStripeOAuthTokens, refreshWithStripe, SandboxIdentityExchange, sandboxDeveloperCredential
} from "./oauth-sandbox-exchange.js";

const credential = Buffer.from("sk_test_harmlessfixture");
const account = "acct_expected";
const session = { userId: "user", authenticatedAt: Date.now(), authVersion: 0 };
const sentinel = "sensitive_token_marker";

function fixture() {
  const state = { callback: vi.fn().mockResolvedValue(true) };
  const read = vi.fn().mockResolvedValue(credential);
  const exchange = vi.fn().mockResolvedValue({
    livemode: false, stripe_user_id: account, access_token: sentinel, refresh_token: sentinel
  });
  return { state, read, exchange, service: new SandboxIdentityExchange("test", state, read, account, exchange) };
}

describe("sandbox OAuth identity exchange", () => {
  it("saves only an expected test account and returns a connected result after durable binding", async () => {
    const { state, read, exchange } = fixture();
    const bind = vi.fn().mockResolvedValueOnce(true).mockRejectedValueOnce(new Error(sentinel));
    const service = new SandboxIdentityExchange("test", state, read, account, exchange, bind);
    exchange.mockResolvedValueOnce({
      livemode: true, stripe_user_id: account, access_token: sentinel, refresh_token: sentinel
    });
    expect(await service.verify(session, "session", "state", "code_test")).toEqual({ ok: false, error: "LIVE_MODE" });
    expect(bind).not.toHaveBeenCalled();
    expect(await service.verify(session, "session", "state", "code_test")).toEqual({
      ok: true, accountId: account, connected: true
    });
    expect(bind).toHaveBeenCalledWith(session, {
      accountId: account, livemode: false, accessToken: sentinel, refreshToken: sentinel
    });
    expect(await service.verify(session, "session", "state", "code_test")).toEqual({ ok: false, error: "BINDING_FAILED" });
  });
  it("returns only the expected test account identity, never tokens", async () => {
    const { service, exchange, state } = fixture();
    const result = await service.verify(session, "session", "state", "code_test");
    expect(result).toEqual({ ok: true, accountId: account });
    expect(JSON.stringify(result)).not.toContain(sentinel);
    expect(state.callback).toHaveBeenCalledOnce();
    expect(exchange).toHaveBeenCalledOnce();
  });

  it("prevents replay and state failures before reading or exchanging credentials", async () => {
    const { service, state, read, exchange } = fixture();
    state.callback.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    expect((await service.verify(session, "session", "state", "code_test")).ok).toBe(true);
    expect(await service.verify(session, "session", "state", "code_test")).toEqual({ ok: false, error: "INVALID_STATE" });
    expect(read).toHaveBeenCalledOnce();
    expect(exchange).toHaveBeenCalledOnce();
  });

  it("fails closed on live mode, missing mode, mismatched and malformed identities", async () => {
    const { service, exchange } = fixture();
    for (const [response, error] of [
      [{ livemode: true, stripe_user_id: account, access_token: sentinel, refresh_token: sentinel }, "LIVE_MODE"],
      [{ stripe_user_id: account, access_token: sentinel, refresh_token: sentinel }, "INVALID_RESPONSE"],
      [{ livemode: false, stripe_user_id: "acct_other", access_token: sentinel, refresh_token: sentinel }, "ACCOUNT_MISMATCH"],
      [{ livemode: false, stripe_user_id: "invalid", access_token: sentinel, refresh_token: sentinel }, "INVALID_RESPONSE"],
      [{ livemode: false, stripe_user_id: account }, "INVALID_RESPONSE"]
    ] as const) {
      exchange.mockResolvedValueOnce(response);
      expect(await service.verify(session, "session", "state", "code_test")).toEqual({ ok: false, error });
    }
  });

  it("sanitizes credential and exchange failures and rejects live keys", async () => {
    const { service, read, exchange } = fixture();
    read.mockRejectedValueOnce(new Error(sentinel)).mockResolvedValueOnce(Buffer.from("sk_live_fake"));
    expect(await service.verify(session, "session", "state", "code_test")).toEqual({ ok: false, error: "CREDENTIAL_UNAVAILABLE" });
    expect(await service.verify(session, "session", "state", "code_test")).toEqual({ ok: false, error: "CREDENTIAL_UNAVAILABLE" });
    exchange.mockRejectedValueOnce(new Error(sentinel));
    const result = await service.verify(session, "session", "state", "code_test");
    expect(result).toEqual({ ok: false, error: "EXCHANGE_FAILED" });
    expect(JSON.stringify(result)).not.toContain(sentinel);
    expect(exchange).toHaveBeenCalledOnce();
  });

  it("requires a pinned server-owned sandbox reference and rejects production", async () => {
    const secrets = { accessVersion: vi.fn().mockResolvedValue(credential) };
    const ref = { secretId: `kp-stripe-oauth-test-${"a".repeat(32)}`, version: "1" };
    expect(await sandboxDeveloperCredential(secrets, ref)()).toEqual(credential);
    expect(secrets.accessVersion).toHaveBeenCalledWith(ref);
    expect(() => sandboxDeveloperCredential(secrets, { ...ref, version: "latest" })).toThrow();
    expect(() => sandboxDeveloperCredential(secrets, { ...ref, secretId: "live-key" })).toThrow();
    const { state, read, exchange } = fixture();
    expect(() => new SandboxIdentityExchange("production", state, read, account, exchange)).toThrow();
    vi.stubEnv("NODE_ENV", "production");
    try {
      expect(() => new SandboxIdentityExchange("development", state, read, account, exchange)).toThrow();
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("uses only the documented Stripe token endpoint with redirects disabled", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ stripe_user_id: account, livemode: false }), { status: 200 })
    );
    try {
      await exchangeWithStripe(credential.toString(), "code_test");
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, options] = fetchMock.mock.calls[0];
      expect(url).toBe("https://api.stripe.com/v1/oauth/token");
      expect(options?.method).toBe("POST");
      expect(options?.redirect).toBe("error");
      expect(options?.body?.toString()).toBe("grant_type=authorization_code&code=code_test");
      expect(options?.headers).toMatchObject({ "stripe-version": "2026-10-28.endive" });
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("uses the documented refresh grant and does not retry an ambiguous failure", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error(sentinel));
    try {
      await expect(refreshWithStripe(credential.toString(), "refresh_token_fixture")).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, options] = fetchMock.mock.calls[0];
      expect(url).toBe("https://api.stripe.com/v1/oauth/token");
      expect(options?.method).toBe("POST");
      expect(options?.redirect).toBe("error");
      expect(options?.body?.toString()).toBe("grant_type=refresh_token&refresh_token=refresh_token_fixture");
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("parses a refreshed token pair with its account and mode", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "new_access", refresh_token: "new_refresh",
        stripe_user_id: account, livemode: true
      }), { status: 200 })
    );
    try {
      const response = await refreshWithStripe(credential.toString(), "previous_refresh");
      expect(parseStripeOAuthTokens(response)).toEqual({
        accessToken: "new_access", refreshToken: "new_refresh", accountId: account, livemode: true
      });
      expect(fetchMock).toHaveBeenCalledOnce();
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("rejects incomplete or malformed token responses", () => {
    const valid = { access_token: "access", refresh_token: "refresh", stripe_user_id: account, livemode: false };
    for (const response of [
      null, { ...valid, refresh_token: "" }, { ...valid, access_token: 1 },
      { ...valid, stripe_user_id: "invalid" }, { ...valid, livemode: "false" }
    ]) {
      expect(parseStripeOAuthTokens(response)).toBeNull();
    }
  });

  it("rejects oversized token responses", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("x".repeat(65537), { status: 200 })
    );
    try {
      await expect(exchangeWithStripe(credential.toString(), "code_test")).rejects.toThrow("response too large");
    } finally {
      fetchMock.mockRestore();
    }
  });
});
