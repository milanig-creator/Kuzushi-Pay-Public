import Stripe from "stripe";
import { z } from "zod";
import type { SecretManager, SecretVersion } from "../secrets/secret-manager.js";
import { CheckoutRecoveryWorker, type CheckoutRecoveryWorkStore } from "./checkout-recovery-worker.js";
import type { CheckoutEventResult } from "./checkout-event-worker.js";
import type { CheckoutReconciliationStore } from "./checkout-reconciliation-store.js";
import type { ReconciliationClient } from "./checkout-reconciler.js";
import type { EmbeddedCheckoutClient } from "./embedded-checkout.js";

type Mode = "TEST" | "LIVE";
export type RecoveryBinding = {
  businessId: string; connectionId: string; accountId: string; mode: Mode; reference: SecretVersion;
};
export interface CheckoutRecoveryBindingStore {
  find(businessId: string, connectionId: string, mode: Mode): Promise<RecoveryBinding | null>;
}
type RecoveryClient = ReconciliationClient & EmbeddedCheckoutClient & {
  balance: { retrieve(): Promise<{ object: string; livemode: boolean }> };
};

export async function verifyRestrictedConnection<Client extends RecoveryClient>(
  secrets: Pick<SecretManager, "accessVersion">,
  reference: SecretVersion,
  mode: Mode,
  accountId: string,
  createClient: (key: string) => Client
): Promise<Client> {
  if (!new RegExp(`^kp-stripe-${mode.toLowerCase()}-[0-9a-f]{32}$`).test(reference.secretId) ||
      !/^[1-9][0-9]*$/.test(reference.version)) throw new Error("Invalid Stripe credential reference");
  const bytes = await secrets.accessVersion(reference);
  const key = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!new RegExp(`^rk_${mode.toLowerCase()}_[A-Za-z0-9]{10,}$`).test(key)) throw new Error("Invalid key");
  const client = createClient(key);
  const account = await client.accounts.retrieveCurrent();
  const balance = await client.balance.retrieve();
  if (account.object !== "account" || account.id !== accountId ||
      balance.object !== "balance" || balance.livemode !== (mode === "LIVE")) {
    throw new Error("Invalid Stripe identity");
  }
  return client;
}

export class CheckoutRecoveryRuntime {
  private cached?: { binding: RecoveryBinding; client: RecoveryClient; checkedAt: number };

  constructor(
    private readonly bindings: CheckoutRecoveryBindingStore,
    private readonly secrets: Pick<SecretManager, "accessVersion">,
    private readonly work: CheckoutRecoveryWorkStore,
    private readonly reconciliation: CheckoutReconciliationStore,
    private readonly businessId: string,
    private readonly connectionId: string,
    private readonly mode: Mode,
    private readonly createClient: (key: string) => RecoveryClient = (key) =>
      new Stripe(key, { apiVersion: "2026-10-28.endive", timeout: 10_000, maxNetworkRetries: 0 })
  ) {
    if (!z.string().uuid().safeParse(businessId).success || !z.string().uuid().safeParse(connectionId).success ||
        !["TEST", "LIVE"].includes(mode)) throw new Error("Invalid checkout recovery configuration");
  }

  async prepare(expectedAccountId?: string): Promise<RecoveryClient> {
    const binding = await this.bindings.find(this.businessId, this.connectionId, this.mode);
    if (!binding || binding.businessId !== this.businessId || binding.connectionId !== this.connectionId ||
        binding.mode !== this.mode || !/^acct_[A-Za-z0-9]+$/.test(binding.accountId) ||
        (expectedAccountId && binding.accountId !== expectedAccountId) ||
        !new RegExp(`^kp-stripe-${this.mode.toLowerCase()}-[0-9a-f]{32}$`).test(binding.reference.secretId) ||
        !/^[1-9][0-9]*$/.test(binding.reference.version)) {
      this.cached = undefined;
      throw new Error("Checkout recovery connection unavailable");
    }
    const cached = this.cached;
    const previous = cached?.binding;
    if (cached && previous && Date.now() >= cached.checkedAt && Date.now() - cached.checkedAt < 60_000 &&
        previous.accountId === binding.accountId && previous.mode === binding.mode &&
        previous.reference.secretId === binding.reference.secretId && previous.reference.version === binding.reference.version) {
      return cached.client;
    }
    this.cached = undefined;
    try {
      const client = await verifyRestrictedConnection(
        this.secrets, binding.reference, this.mode, binding.accountId, this.createClient
      );
      this.cached = {
        binding: { ...binding, reference: { ...binding.reference } },
        client,
        checkedAt: Date.now()
      };
      return client;
    } catch {
      throw new Error("Checkout recovery credential verification failed");
    }
  }

  async processOne(): Promise<CheckoutEventResult> {
    const client = await this.prepare();
    return new CheckoutRecoveryWorker(
      this.work, this.reconciliation, client, this.businessId, this.connectionId
    ).processOne();
  }
}
