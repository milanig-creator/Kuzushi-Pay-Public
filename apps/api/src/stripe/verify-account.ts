import Stripe from "stripe";

type AccountResult = { id: string; object: string };
type RetrieveAccount = (key: string) => Promise<AccountResult>;

export type VerificationResult =
  | { ok: true; accountId: string; environment: "test-key-authenticated-mode-unconfirmed" }
  | { ok: false; error: "invalid-input" | "permission-denied" | "authentication-failed" |
      "account-mismatch" | "invalid-response" | "request-failed" };

export async function verifyAccount(
  key: string, expectedAccountId: string,
  retrieve: RetrieveAccount = async (credential) => {
    const stripe = new Stripe(credential, {
      apiVersion: "2026-10-28.endive", timeout: 15000, maxNetworkRetries: 0
    });
    return stripe.accounts.retrieveCurrent();
  }
): Promise<VerificationResult> {
  if (!/^rk_test_[A-Za-z0-9]{10,}$/.test(key) ||
      !/^acct_[A-Za-z0-9]+$/.test(expectedAccountId)) {
    return { ok: false, error: "invalid-input" };
  }
  let account: AccountResult;
  try {
    account = await retrieve(key);
  } catch (error) {
    const status = error && typeof error === "object" && "statusCode" in error ? error.statusCode : undefined;
    if (status === 403) return { ok: false, error: "permission-denied" };
    if (status === 401) return { ok: false, error: "authentication-failed" };
    return { ok: false, error: "request-failed" };
  }
  if (!account || account.object !== "account" || typeof account.id !== "string" ||
      !/^acct_[A-Za-z0-9]+$/.test(account.id)) {
    return { ok: false, error: "invalid-response" };
  }
  if (account.id !== expectedAccountId) return { ok: false, error: "account-mismatch" };
  return { ok: true, accountId: account.id, environment: "test-key-authenticated-mode-unconfirmed" };
}
