import type Stripe from "stripe";
import type { PrismaClient } from "../generated/prisma/client.js";

export class ConnectOnboarding {
  constructor(
    private readonly core: Pick<Stripe["v2"]["core"], "accounts" | "accountLinks">,
    private readonly appOrigin: string,
    private readonly live: boolean
  ) {
    const origin = new URL(appOrigin);
    if (origin.protocol !== "https:" || origin.origin !== appOrigin) {
      throw new Error("Stripe onboarding requires an exact HTTPS app origin");
    }
  }

  async createAccount(provisioningId: string) {
    const account = await this.core.accounts.create({
      dashboard: "full",
      defaults: { responsibilities: { fees_collector: "stripe", losses_collector: "stripe" } },
      configuration: { merchant: { capabilities: { card_payments: { requested: true } } } }
    }, { idempotencyKey: `kuzushi-connect-${provisioningId}` });
    this.verifyAccount(account, account.id);
    return account.id;
  }

  async createLink(accountId: string, businessId: string) {
    const callback = new URL(this.appOrigin);
    callback.searchParams.set("stripe_connect", "return");
    callback.searchParams.set("business", businessId);
    const refresh = new URL(callback);
    refresh.searchParams.set("stripe_connect", "refresh");
    const link = await this.core.accountLinks.create({
      account: accountId,
      use_case: {
        type: "account_onboarding",
        account_onboarding: {
          return_url: callback.href, refresh_url: refresh.href,
          collection_options: { fields: "eventually_due" }
        }
      }
    });
    const url = new URL(link.url);
    if (link.account !== accountId || link.livemode !== this.live ||
        url.origin !== "https://accounts.stripe.com" || url.username || url.password) {
      throw new Error("Unexpected Stripe onboarding link");
    }
    return url.href;
  }

  async paymentsEnabled(accountId: string) {
    const account = await this.core.accounts.retrieve(accountId, { include: ["configuration.merchant"] });
    this.verifyAccount(account, accountId);
    return !account.closed && account.configuration?.merchant?.capabilities?.card_payments?.status === "active";
  }

  private verifyAccount(account: { id: string; livemode: boolean }, expectedId: string) {
    if (!/^acct_[A-Za-z0-9]+$/.test(account.id) || account.id !== expectedId || account.livemode !== this.live) {
      throw new Error("Unexpected Stripe connected account");
    }
  }
}

export class ConnectOnboardingStore {
  constructor(private readonly db: PrismaClient, private readonly stripe: ConnectOnboarding,
    private readonly mode: "LIVE" | "TEST") {}

  private find(businessId: string) {
    return this.db.stripeConnection.findUnique({ where: { businessId_mode: { businessId, mode: this.mode } } });
  }

  async status(businessId: string) {
    const connection = await this.find(businessId);
    if (!connection) return "available";
    if (!connection.connectProvisionedAt || connection.status === "DISCONNECTED") return "unavailable";
    if (!connection.stripeAccountId) return "pending";
    return await this.stripe.paymentsEnabled(connection.stripeAccountId) ? "connected" : "pending";
  }

  async start(businessId: string, stillAuthorized: () => Promise<boolean>) {
    await this.db.stripeConnection.createMany({
      data: { businessId, mode: this.mode, connectProvisionedAt: new Date() }, skipDuplicates: true
    });
    const connection = await this.find(businessId);
    if (!connection?.connectProvisionedAt || connection.status === "DISCONNECTED") return null;
    let accountId = connection.stripeAccountId;
    if (!accountId) {
      // Stop retrying before Stripe can discard the idempotency key.
      if (Date.now() - connection.connectProvisionedAt.getTime() >= 12 * 60 * 60 * 1000) return null;
      accountId = await this.stripe.createAccount(connection.id);
      const saved = await this.db.stripeConnection.updateMany({
        where: { id: connection.id, status: "PENDING_VERIFICATION", OR: [{ stripeAccountId: null }, { stripeAccountId: accountId }] },
        data: { stripeAccountId: accountId }
      });
      if (!saved.count) return null;
    }
    if (!await stillAuthorized()) return null;
    const link = await this.stripe.createLink(accountId, businessId);
    return await stillAuthorized() ? link : null;
  }
}
