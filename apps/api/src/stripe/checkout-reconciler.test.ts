import { createServer } from "node:http";
import Stripe from "stripe";
import { describe, expect, it, vi } from "vitest";
import type { CheckoutReconciliationContext } from "./checkout-reconciliation-store.js";
import { CheckoutReconciler } from "./checkout-reconciler.js";
import { CheckoutEventRunner, CheckoutEventWorker, type CheckoutEventResult } from "./checkout-event-worker.js";
import { CheckoutRecoveryWorker } from "./checkout-recovery-worker.js";
import { CheckoutRecoveryRuntime, type RecoveryBinding } from "./checkout-recovery-runtime.js";

const businessId = "530d5894-4c02-43dc-afaf-d5df45c1866b";
const connectionId = "471b9e63-3c33-43f0-a411-594cc4a4b7f4";
const publicationId = "ac6da013-9562-4c87-b7e8-0bccdc851b08";
const orderId = "ee802b80-5c49-46b4-8e02-d834feaa67e0";
const attemptId = "156e0fb6-3441-444b-94fb-fe6945b733c4";
const eventId = "evt_123";
const now = new Date();
const context: CheckoutReconciliationContext = {
  event: {
    id: eventId, businessId, connectionId, stripeAccountId: "acct_123", mode: "TEST",
    source: "direct", type: "checkout.session.completed", sessionId: "cs_test_123",
    eventCreated: BigInt(1700000000), receivedAt: now
  },
  order: { id: orderId, publicationId, initialPaymentStatus: "UNPAID", paidQuantity: null, createdAt: now },
  attempt: {
    id: attemptId, orderId, status: "SESSION_CREATED", operationId: null, claimedAt: null,
    stripeSessionId: "cs_test_123", createdAt: now, updatedAt: now
  },
  publication: {
    id: publicationId, businessId, connectionId, draftId: "a256689b-32dc-451c-8701-4b2f09b58c31",
    actorId: "bb3f4ea1-f776-4d18-80c2-78fed1e83634", actorSessionVersion: 1,
    stripeAccountId: "acct_123", mode: "TEST", name: "Service", description: "", kind: "SERVICE",
    amountCents: 5000, currency: "USD", billing: "ONE_TIME", interval: null, status: "PRICE_CREATED",
    operationId: null, claimedAt: null, stripeProductId: "prod_123", stripePriceId: "price_123",
    createdAt: now, updatedAt: now
  }
};
const session = {
  id: "cs_test_123", object: "checkout.session", livemode: false, status: "complete", mode: "payment",
  ui_mode: "embedded_page", payment_status: "paid", currency: "usd", amount_total: 10000,
  automatic_tax: { enabled: true }, metadata: { kuzushi_order_id: orderId, kuzushi_attempt_id: attemptId }
};
const price = {
  id: "price_123", object: "price", active: true, livemode: false, currency: "usd", unit_amount: 5000,
  type: "one_time", product: "prod_123", billing_scheme: "per_unit", custom_unit_amount: null,
  transform_quantity: null, recurring: null
};
const lines = { object: "list", has_more: false, data: [{ object: "item", quantity: 2, currency: "usd", price }] };
function setup() {
  const store = {
    find: vi.fn().mockResolvedValue(context), record: vi.fn().mockResolvedValue(undefined),
    findAttempt: vi.fn().mockResolvedValue(context), recordAttempt: vi.fn().mockResolvedValue(undefined)
  };
  const client = {
    accounts: { retrieveCurrent: vi.fn().mockResolvedValue({ object: "account", id: "acct_123" }) },
    checkout: { sessions: { retrieve: vi.fn().mockResolvedValue(session), listLineItems: vi.fn().mockResolvedValue(lines) } }
  };
  return { reconciler: new CheckoutReconciler(store, client, businessId, connectionId), store, client };
}

describe("checkout recovery runtime", () => {
  function runtimeSetup() {
    const binding: RecoveryBinding = {
      businessId, connectionId, accountId: "acct_123", mode: "TEST",
      reference: { secretId: `kp-stripe-test-${"a".repeat(32)}`, version: "1" }
    };
    const bindings = { find: vi.fn().mockResolvedValue(binding) };
    const secrets = { accessVersion: vi.fn().mockResolvedValue(new TextEncoder().encode("rk_test_abcdefghij")) };
    const work = { claim: vi.fn().mockResolvedValue(null), complete: vi.fn(), retry: vi.fn() };
    const { store, client: reconciliationClient } = setup();
    const client = {
      ...reconciliationClient,
      balance: { retrieve: vi.fn().mockResolvedValue({ object: "balance", livemode: false }) }
    };
    const createClient = vi.fn().mockReturnValue(client);
    const runtime = new CheckoutRecoveryRuntime(bindings, secrets, work, store, businessId, connectionId, "TEST", createClient);
    return { binding, bindings, secrets, work, client, createClient, runtime };
  }

  it("uses only the verified business binding and reloads a rotated secret version", async () => {
    const { binding, bindings, secrets, work, client, runtime } = runtimeSetup();
    await expect(runtime.processOne()).resolves.toEqual({ state: "idle" });
    await runtime.processOne();
    expect(bindings.find).toHaveBeenCalledWith(businessId, connectionId, "TEST");
    expect(secrets.accessVersion).toHaveBeenCalledTimes(1);
    expect(work.claim).toHaveBeenCalledTimes(2);
    bindings.find.mockResolvedValue({ ...binding, reference: { ...binding.reference, version: "2" } });
    client.accounts.retrieveCurrent.mockResolvedValueOnce({ object: "account", id: "acct_other" });
    await expect(runtime.processOne()).rejects.toThrow("Checkout recovery credential verification failed");
    expect(work.claim).toHaveBeenCalledTimes(2);
    await runtime.processOne();
    expect(secrets.accessVersion).toHaveBeenLastCalledWith({ ...binding.reference, version: "2" });
    expect(work.claim).toHaveBeenCalledTimes(3);
  });

  it("fails closed when the binding is disconnected, mis-scoped, or has an invalid mode", async () => {
    const { binding, bindings, secrets, work, runtime } = runtimeSetup();
    await runtime.processOne();
    bindings.find.mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ ...binding, businessId: "e8c1f3a5-65a0-4c12-8d75-9cc1055dd103" })
      .mockResolvedValueOnce({ ...binding, reference: { ...binding.reference, version: "latest" } });
    for (let i = 0; i < 3; i++) {
      await expect(runtime.processOne()).rejects.toThrow("Checkout recovery connection unavailable");
    }
    expect(secrets.accessVersion).toHaveBeenCalledTimes(1);
    expect(work.claim).toHaveBeenCalledTimes(1);
    secrets.accessVersion.mockResolvedValueOnce(new TextEncoder().encode("rk_live_abcdefghij"));
    await expect(runtime.processOne()).rejects.toThrow("Checkout recovery credential verification failed");
    expect(work.claim).toHaveBeenCalledTimes(1);
  });

  it("rechecks the pinned secret and Stripe mode after the cache expires", async () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(100_000);
    try {
      const { secrets, client, work, runtime } = runtimeSetup();
      await runtime.processOne();
      clock.mockReturnValue(160_000);
      secrets.accessVersion.mockRejectedValueOnce(new Error("private secret-manager error"));
      await expect(runtime.processOne()).rejects.toThrow("Checkout recovery credential verification failed");
      client.balance.retrieve.mockResolvedValueOnce({ object: "balance", livemode: true });
      await expect(runtime.processOne()).rejects.toThrow("Checkout recovery credential verification failed");
      expect(work.claim).toHaveBeenCalledTimes(1);
      await runtime.processOne();
      expect(work.claim).toHaveBeenCalledTimes(2);
    } finally {
      clock.mockRestore();
    }
  });
});

describe("checkout event worker", () => {
  it("reports retries without leaking errors and caps backoff", async () => {
    const { store, client } = setup();
    const work = {
      claim: vi.fn().mockResolvedValue({ eventId, leaseToken: "lease", attemptCount: 100 }),
      complete: vi.fn(),
      retry: vi.fn().mockResolvedValue(true)
    };
    const worker = new CheckoutEventWorker(work, store, client, businessId, connectionId);
    store.find.mockRejectedValueOnce(new Error("sensitive database error"));
    await expect(worker.processOne()).resolves.toEqual({ state: "retry", error: "INTERNAL_ERROR" });
    expect(work.claim).toHaveBeenCalledWith(businessId, connectionId, expect.any(String));
    expect(work.retry).toHaveBeenCalledWith(eventId, "lease", "INTERNAL_ERROR", 3600);
    expect(work.complete).not.toHaveBeenCalled();
  });

  it("reports a lost lease rather than claiming success or a scheduled retry", async () => {
    const { store, client } = setup();
    const work = {
      claim: vi.fn().mockResolvedValue({ eventId, leaseToken: "lease", attemptCount: 1 }),
      complete: vi.fn().mockResolvedValue(false),
      retry: vi.fn().mockResolvedValue(false)
    };
    const worker = new CheckoutEventWorker(work, store, client, businessId, connectionId);
    await expect(worker.processOne()).resolves.toEqual({ state: "lease-lost" });
    store.find.mockResolvedValueOnce(null);
    await expect(worker.processOne()).resolves.toEqual({ state: "lease-lost" });
    expect(work.retry).toHaveBeenCalledWith(eventId, "lease", "NOT_READY", 30);
  });
});

describe("checkout recovery worker", () => {
  it("rechecks unpaid sessions later and completes expired or paid sessions", async () => {
    const { store, client } = setup();
    const work = {
      claim: vi.fn().mockResolvedValue({ attemptId, leaseToken: "lease", attemptCount: 2, alreadyPaid: false }),
      complete: vi.fn().mockResolvedValue(true),
      retry: vi.fn().mockResolvedValue(true)
    };
    const worker = new CheckoutRecoveryWorker(work, store, client, businessId, connectionId);
    client.checkout.sessions.retrieve.mockResolvedValueOnce({ ...session, status: "open", payment_status: "unpaid" });
    await expect(worker.processOne()).resolves.toEqual({ state: "deferred" });
    expect(work.retry).toHaveBeenCalledWith(attemptId, "lease", null, 600);
    client.checkout.sessions.retrieve.mockResolvedValueOnce({ ...session, status: "complete", payment_status: "unpaid" });
    await expect(worker.processOne()).resolves.toEqual({ state: "deferred" });
    client.checkout.sessions.retrieve.mockResolvedValueOnce({ ...session, status: "expired", payment_status: "unpaid" });
    await expect(worker.processOne()).resolves.toEqual({ state: "completed", observedStatus: "UNPAID" });
    await expect(worker.processOne()).resolves.toEqual({ state: "completed", observedStatus: "PAID" });
    expect(work.complete).toHaveBeenCalledTimes(2);
  });

  it("retries failures without leaking details and detects a lost lease", async () => {
    const { store, client } = setup();
    const work = {
      claim: vi.fn().mockResolvedValue({ attemptId, leaseToken: "lease", attemptCount: 100, alreadyPaid: false }),
      complete: vi.fn().mockResolvedValue(false),
      retry: vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false)
    };
    const worker = new CheckoutRecoveryWorker(work, store, client, businessId, connectionId);
    client.accounts.retrieveCurrent.mockRejectedValueOnce(new Error("private provider error"));
    await expect(worker.processOne()).resolves.toEqual({ state: "retry", error: "STRIPE_UNAVAILABLE" });
    expect(work.retry).toHaveBeenCalledWith(attemptId, "lease", "STRIPE_UNAVAILABLE", 3600);
    client.accounts.retrieveCurrent.mockRejectedValueOnce(new Error("private provider error"));
    await expect(worker.processOne()).resolves.toEqual({ state: "lease-lost" });
    await expect(worker.processOne()).resolves.toEqual({ state: "lease-lost" });
  });

  it("finishes an already-confirmed payment without another Stripe request", async () => {
    const { store, client } = setup();
    const work = {
      claim: vi.fn().mockResolvedValue({ attemptId, leaseToken: "lease", attemptCount: 1, alreadyPaid: true }),
      complete: vi.fn().mockResolvedValue(true),
      retry: vi.fn()
    };
    const worker = new CheckoutRecoveryWorker(work, store, client, businessId, connectionId);
    await expect(worker.processOne()).resolves.toEqual({ state: "completed", observedStatus: "PAID" });
    expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
    expect(store.recordAttempt).not.toHaveBeenCalled();
  });
});

describe("checkout event runner", () => {
  it("reports retries and drains a bounded batch without overlapping timers", async () => {
    vi.useFakeTimers();
    try {
      const worker = {
        processOne: vi.fn<() => Promise<CheckoutEventResult>>()
          .mockResolvedValueOnce({ state: "retry", error: "NOT_READY" })
          .mockResolvedValue({ state: "completed", observedStatus: "PAID" })
      };
      const report = vi.fn();
      const runner = new CheckoutEventRunner(worker, report);
      runner.start();
      runner.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(worker.processOne).toHaveBeenCalledTimes(20);
      expect(report).toHaveBeenCalledExactlyOnceWith({ state: "retry", error: "NOT_READY" });
      await vi.advanceTimersByTimeAsync(4999);
      expect(worker.processOne).toHaveBeenCalledTimes(20);
      worker.processOne.mockResolvedValue({ state: "idle" });
      await vi.advanceTimersByTimeAsync(1);
      expect(worker.processOne).toHaveBeenCalledTimes(21);
      await runner.stop();
      await vi.advanceTimersByTimeAsync(5000);
      expect(worker.processOne).toHaveBeenCalledTimes(21);
    } finally {
      vi.useRealTimers();
    }
  });

  it("waits for in-flight work during shutdown and prevents premature restart", async () => {
    vi.useFakeTimers();
    try {
      let finish: (result: CheckoutEventResult) => void = () => { throw new Error("Missing work"); };
      const work = new Promise<CheckoutEventResult>((resolve) => { finish = resolve; });
      const worker = {
        processOne: vi.fn<() => Promise<CheckoutEventResult>>()
          .mockReturnValueOnce(work).mockResolvedValue({ state: "idle" })
      };
      const report = vi.fn();
      const runner = new CheckoutEventRunner(worker, report);
      runner.start();
      await vi.advanceTimersByTimeAsync(10_000);
      expect(worker.processOne).toHaveBeenCalledTimes(1);
      let stopped = false;
      const stopping = runner.stop().then(() => { stopped = true; });
      await Promise.resolve();
      expect(stopped).toBe(false);
      expect(() => runner.start()).toThrow("Checkout event runner is stopping");
      finish({ state: "lease-lost" });
      await stopping;
      expect(report).toHaveBeenCalledExactlyOnceWith({ state: "lease-lost" });
      await vi.advanceTimersByTimeAsync(5000);
      expect(worker.processOne).toHaveBeenCalledTimes(1);
      runner.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(worker.processOne).toHaveBeenCalledTimes(2);
      await runner.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it("surfaces worker and reporter failures without leaking their details, then resumes", async () => {
    vi.useFakeTimers();
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const worker = {
        processOne: vi.fn<() => Promise<CheckoutEventResult>>()
          .mockRejectedValueOnce(new Error("sensitive database failure"))
          .mockResolvedValue({ state: "idle" })
      };
      const report = vi.fn().mockRejectedValueOnce(new Error("sensitive logging failure"));
      const runner = new CheckoutEventRunner(worker, report);
      runner.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(report).toHaveBeenCalledExactlyOnceWith({ state: "runner-error" });
      expect(log).toHaveBeenCalledExactlyOnceWith("Checkout event worker reporting failed", { state: "runner-error" });
      await vi.advanceTimersByTimeAsync(5000);
      expect(worker.processOne).toHaveBeenCalledTimes(2);
      await runner.stop();
    } finally {
      log.mockRestore();
      vi.useRealTimers();
    }
  });
});

describe("checkout payment reconciliation", () => {
  it("uses a live OAuth client for the publication account and verifies the paid session and price", async () => {
    const { store, client } = setup();
    const liveSessionId = "cs_live_123";
    store.findAttempt.mockResolvedValue({ ...context,
      attempt: { ...context.attempt, stripeSessionId: liveSessionId },
      publication: { ...context.publication, mode: "LIVE" }
    });
    client.checkout.sessions.retrieve.mockResolvedValue({ ...session, id: liveSessionId, livemode: true });
    client.checkout.sessions.listLineItems.mockResolvedValue({ ...lines,
      data: [{ ...lines.data[0], price: { ...price, livemode: true } }]
    });
    const loadLiveClient = vi.fn().mockResolvedValue({ checkout: client.checkout });
    const reconciler = new CheckoutReconciler(store, { loadLiveClient }, businessId, connectionId);
    await expect(reconciler.reconcileAttempt(attemptId)).resolves.toEqual({ observedStatus: "PAID", sessionStatus: "complete" });
    expect(loadLiveClient).toHaveBeenCalledExactlyOnceWith(context.publication.stripeAccountId);
    expect(client.checkout.sessions.retrieve).toHaveBeenCalledExactlyOnceWith(liveSessionId);
    expect(store.recordAttempt).toHaveBeenCalledOnce();

    loadLiveClient.mockRejectedValueOnce(new Error("private credential error"));
    await expect(reconciler.reconcileAttempt(attemptId)).rejects.toMatchObject({ code: "STRIPE_UNAVAILABLE" });
    expect(store.recordAttempt).toHaveBeenCalledOnce();
  });

  it("rejects a test-mode checkout before loading a live OAuth credential", async () => {
    const { store } = setup();
    const loadLiveClient = vi.fn();
    const reconciler = new CheckoutReconciler(store, { loadLiveClient }, businessId, connectionId);
    await expect(reconciler.reconcileAttempt(attemptId)).rejects.toMatchObject({ code: "NOT_READY" });
    expect(loadLiveClient).not.toHaveBeenCalled();
    expect(store.recordAttempt).not.toHaveBeenCalled();
  });

  it("reconciles an independently recorded session without creating an event result", async () => {
    const { reconciler, store, client } = setup();
    await expect(reconciler.reconcileAttempt(attemptId))
      .resolves.toEqual({ observedStatus: "PAID", sessionStatus: "complete" });
    expect(store.findAttempt).toHaveBeenCalledWith(businessId, connectionId, attemptId);
    expect(store.recordAttempt).toHaveBeenCalledWith(
      businessId, connectionId, attemptId, orderId, "cs_test_123", { status: "PAID", quantity: 2 }
    );
    expect(client.checkout.sessions.listLineItems).toHaveBeenCalledOnce();
    expect(store.record).not.toHaveBeenCalled();
  });

  it("records an open, unpaid session without claiming payment", async () => {
    const { reconciler, store, client } = setup();
    client.checkout.sessions.retrieve.mockResolvedValue({ ...session, status: "open", payment_status: "unpaid" });
    await expect(reconciler.reconcileAttempt(attemptId))
      .resolves.toEqual({ observedStatus: "UNPAID", sessionStatus: "open" });
    expect(store.recordAttempt).toHaveBeenCalledWith(
      businessId, connectionId, attemptId, orderId, "cs_test_123", { status: "UNPAID", quantity: null }
    );
    expect(client.checkout.sessions.listLineItems).not.toHaveBeenCalled();
  });

  it("rejects unavailable, mismatched and untrusted session recovery contexts", async () => {
    const { reconciler, store, client } = setup();
    await expect(reconciler.reconcileAttempt("invalid")).rejects.toMatchObject({ code: "NOT_READY" });
    store.findAttempt.mockResolvedValueOnce(null).mockResolvedValueOnce({
      ...context, attempt: { ...context.attempt, id: "another" }
    }).mockResolvedValueOnce({
      ...context, publication: { ...context.publication, businessId: "another" }
    }).mockResolvedValueOnce({
      ...context, attempt: { ...context.attempt, stripeSessionId: "cs_live_123" }
    });
    for (let count = 0; count < 4; count++) {
      await expect(reconciler.reconcileAttempt(attemptId)).rejects.toMatchObject({ code: "NOT_READY" });
    }
    expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
    expect(store.recordAttempt).not.toHaveBeenCalled();
    client.accounts.retrieveCurrent.mockResolvedValueOnce({ object: "account", id: "acct_other" });
    await expect(reconciler.reconcileAttempt(attemptId)).rejects.toMatchObject({ code: "INVALID_STRIPE_RESPONSE" });
    expect(store.recordAttempt).not.toHaveBeenCalled();
  });

  it("records paid only after retrieving the account, session and final Stripe line items", async () => {
    const { reconciler, store, client } = setup();
    await expect(reconciler.reconcile(eventId)).resolves.toEqual({ observedStatus: "PAID" });
    expect(store.find).toHaveBeenCalledWith(businessId, connectionId, eventId);
    expect(client.checkout.sessions.listLineItems).toHaveBeenCalledWith("cs_test_123", { limit: 2 });
    expect(store.record).toHaveBeenCalledWith(businessId, connectionId, eventId, orderId, { status: "PAID", quantity: 2 });
  });

  it("keeps delayed payments unpaid and retries when a success event has not settled", async () => {
    const { reconciler, store, client } = setup();
    client.checkout.sessions.retrieve.mockResolvedValue({ ...session, payment_status: "unpaid" });
    await expect(reconciler.reconcile(eventId)).resolves.toEqual({ observedStatus: "UNPAID" });
    expect(client.checkout.sessions.listLineItems).not.toHaveBeenCalled();
    expect(store.record).toHaveBeenCalledWith(businessId, connectionId, eventId, orderId, { status: "UNPAID", quantity: null });
    store.record.mockClear();
    store.find.mockResolvedValue({ ...context, event: { ...context.event, type: "checkout.session.async_payment_succeeded" } });
    await expect(reconciler.reconcile(eventId)).rejects.toMatchObject({ code: "NOT_READY" });
    expect(store.record).not.toHaveBeenCalled();
  });

  it("does not act on missing or cross-business records", async () => {
    const { reconciler, store, client } = setup();
    store.find.mockResolvedValueOnce(null).mockResolvedValueOnce({
      ...context, publication: { ...context.publication, businessId: "wrong" }
    });
    await expect(reconciler.reconcile(eventId)).rejects.toMatchObject({ code: "NOT_READY" });
    await expect(reconciler.reconcile(eventId)).rejects.toMatchObject({ code: "NOT_READY" });
    expect(client.accounts.retrieveCurrent).not.toHaveBeenCalled();
    expect(store.record).not.toHaveBeenCalled();
  });

  it("refuses mismatched Stripe account, session, mode, tax, metadata or payment status", async () => {
    for (const mismatch of [
      { livemode: true }, { id: "cs_test_other" }, { mode: "subscription" }, { status: "open" },
      { payment_status: "no_payment_required" }, { automatic_tax: { enabled: false } },
      { metadata: { kuzushi_order_id: "other", kuzushi_attempt_id: attemptId } }
    ]) {
      const { reconciler, store, client } = setup();
      client.checkout.sessions.retrieve.mockResolvedValueOnce({ ...session, ...mismatch });
      await expect(reconciler.reconcile(eventId)).rejects.toThrow();
      expect(store.record).not.toHaveBeenCalled();
    }
    const { reconciler, store, client } = setup();
    client.accounts.retrieveCurrent.mockResolvedValueOnce({ object: "account", id: "acct_other" });
    await expect(reconciler.reconcile(eventId)).rejects.toMatchObject({ code: "INVALID_STRIPE_RESPONSE" });
    expect(store.record).not.toHaveBeenCalled();
  });

  it("requires exactly one matching line item and a quantity of 1 through 50", async () => {
    for (const bad of [
      { has_more: true }, { data: [] }, { data: [lines.data[0], lines.data[0]] },
      { data: [{ ...lines.data[0], quantity: 0 }] }, { data: [{ ...lines.data[0], quantity: 51 }] },
      { data: [{ ...lines.data[0], price: { ...price, unit_amount: 1 } }] },
      { data: [{ ...lines.data[0], price: { ...price, product: "prod_other" } }] }
    ]) {
      const { reconciler, store, client } = setup();
      client.checkout.sessions.listLineItems.mockResolvedValueOnce({ ...lines, ...bad });
      await expect(reconciler.reconcile(eventId)).rejects.toMatchObject({ code: "INVALID_STRIPE_RESPONSE" });
      expect(store.record).not.toHaveBeenCalled();
    }
  });

  it("accepts a historical price archived after purchase", async () => {
    const { reconciler, client } = setup();
    client.checkout.sessions.listLineItems.mockResolvedValueOnce({
      ...lines, data: [{ ...lines.data[0], price: { ...price, active: false } }]
    });
    await expect(reconciler.reconcile(eventId)).resolves.toEqual({ observedStatus: "PAID" });
  });

  it("verifies the initial payment of a subscription without claiming later renewals", async () => {
    const { reconciler, client, store } = setup();
    store.find.mockResolvedValue({
      ...context, publication: { ...context.publication, billing: "RECURRING", interval: "MONTH" }
    });
    client.checkout.sessions.retrieve.mockResolvedValue({ ...session, mode: "subscription" });
    client.checkout.sessions.listLineItems.mockResolvedValue({
      ...lines, data: [{ ...lines.data[0], price: {
        ...price, type: "recurring",
        recurring: { interval: "month", interval_count: 1, usage_type: "licensed", trial_period_days: null }
      } }]
    });
    await expect(reconciler.reconcile(eventId)).resolves.toEqual({ observedStatus: "PAID" });
  });

  it("categorizes Stripe failures without returning provider details", async () => {
    const { reconciler, client, store } = setup();
    client.accounts.retrieveCurrent.mockRejectedValueOnce(new Error("sensitive provider message"));
    await expect(reconciler.reconcile(eventId)).rejects.toMatchObject({ code: "STRIPE_UNAVAILABLE", message: "STRIPE_UNAVAILABLE" });
    expect(store.record).not.toHaveBeenCalled();
  });

  it("uses the Stripe SDK to retrieve a session and line items over loopback", async () => {
    const paths: string[] = [];
    const server = createServer((req, res) => {
      paths.push(req.url ?? "");
      const data = req.url === "/v1/account" ? { object: "account", id: "acct_123" } :
        req.url?.startsWith("/v1/checkout/sessions/cs_test_123/line_items") ? lines : session;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(data));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing test server address");
      const stripe = new Stripe("rk_test_placeholder", {
        host: "127.0.0.1", port: address.port, protocol: "http",
        apiVersion: "2026-10-28.endive", maxNetworkRetries: 0
      });
      const { store } = setup();
      const reconciler = new CheckoutReconciler(store, stripe, businessId, connectionId);
      await expect(reconciler.reconcile(eventId)).resolves.toEqual({ observedStatus: "PAID" });
      expect(paths).toEqual([
        "/v1/account", "/v1/checkout/sessions/cs_test_123", "/v1/checkout/sessions/cs_test_123/line_items?limit=2"
      ]);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
