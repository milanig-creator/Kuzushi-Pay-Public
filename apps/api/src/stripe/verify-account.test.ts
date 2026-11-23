import { describe, expect, it, vi } from "vitest";
import { createServer } from "node:http";
import Stripe from "stripe";
import { verifyAccount } from "./verify-account.js";

const key = `rk_test_${"a".repeat(24)}`;
const accountId = "acct_123456";

describe("test-only Stripe account verifier", () => {
  it("verifies the returned account matches the independently supplied ID", async () => {
    const retrieve = vi.fn().mockResolvedValue({ id: accountId, object: "account", confidential: "not returned" });
    expect(await verifyAccount(key, accountId, retrieve)).toEqual({
      ok: true, accountId, environment: "test-key-authenticated-mode-unconfirmed"
    });
    expect(retrieve).toHaveBeenCalledOnce();
    expect(retrieve).toHaveBeenCalledWith(key);
  });

  it("refuses live keys, unrestricted keys and invalid account IDs before any request", async () => {
    const retrieve = vi.fn();
    for (const [candidate, expected] of [
      [`rk_live_${"a".repeat(24)}`, accountId],
      [`sk_test_${"a".repeat(24)}`, accountId],
      ["", accountId],
      [key, "not-an-account"]
    ]) {
      expect(await verifyAccount(candidate, expected, retrieve)).toEqual({ ok: false, error: "invalid-input" });
    }
    expect(retrieve).not.toHaveBeenCalled();
  });

  it("fails closed on mismatched or malformed account responses", async () => {
    expect(await verifyAccount(key, accountId, async () => ({ id: "acct_other", object: "account" })))
      .toEqual({ ok: false, error: "account-mismatch" });
    expect(await verifyAccount(key, accountId, async () => ({ id: accountId, object: "wrong" })))
      .toEqual({ ok: false, error: "invalid-response" });
  });

  it("categorizes failures without exposing provider messages or credentials", async () => {
    for (const [statusCode, expected] of [[403, "permission-denied"], [401, "authentication-failed"], [500, "request-failed"]] as const) {
      const retrieve = async () => { throw { statusCode, message: key }; };
      expect(await verifyAccount(key, accountId, retrieve)).toEqual({ ok: false, error: expected });
    }
  });

  it("uses the pinned SDK self-account endpoint and API version", async () => {
    let path: string | undefined;
    let method: string | undefined;
    let version: string | string[] | undefined;
    const server = createServer((req, res) => {
      path = req.url;
      method = req.method;
      version = req.headers["stripe-version"];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: accountId, object: "account" }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing test server address");
      const stripe = new Stripe(key, {
        host: "127.0.0.1", port: address.port, protocol: "http",
        apiVersion: "2026-10-28.endive", maxNetworkRetries: 0
      });
      expect(await verifyAccount(key, accountId, () => stripe.accounts.retrieveCurrent()))
        .toEqual({ ok: true, accountId, environment: "test-key-authenticated-mode-unconfirmed" });
      expect(method).toBe("GET");
      expect(path).toBe("/v1/account");
      expect(version).toBe("2026-10-28.endive");
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
