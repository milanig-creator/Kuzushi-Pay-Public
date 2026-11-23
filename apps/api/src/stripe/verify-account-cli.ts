import { verifyAccount } from "./verify-account.js";

const key = process.env.KUZUSHI_STRIPE_TEST_KEY ?? "";
const expected = process.env.KUZUSHI_STRIPE_EXPECTED_ACCOUNT_ID ?? "";
delete process.env.KUZUSHI_STRIPE_TEST_KEY;
delete process.env.KUZUSHI_STRIPE_EXPECTED_ACCOUNT_ID;

try {
  const result = await verifyAccount(key, expected);
  if (result.ok) {
    console.log(`Account ID: ${result.accountId}`);
    console.log("Account comparison: match");
    console.log("Environment: test-key prefix authenticated; Stripe response does not independently confirm mode.");
  } else {
    const messages = {
      "invalid-input": "Invalid test restricted key format or expected account ID.",
      "permission-denied": "Stripe denied access. Check the restricted key's account-read permission.",
      "authentication-failed": "Stripe rejected authentication. Check the test key.",
      "account-mismatch": "Stripe account ID does not match the independently supplied account ID.",
      "invalid-response": "Stripe returned an invalid account response.",
      "request-failed": "Stripe account request failed; check connectivity and permissions."
    };
    console.error(messages[result.error]);
    process.exitCode = 1;
  }
} catch {
  console.error("Stripe verification failed unexpectedly.");
  process.exitCode = 1;
}
