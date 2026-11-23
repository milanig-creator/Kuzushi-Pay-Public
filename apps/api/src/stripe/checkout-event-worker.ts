import { randomUUID } from "node:crypto";
import {
  CheckoutReconciler, CheckoutReconciliationError, type ReconciliationClient
} from "./checkout-reconciler.js";
import type { CheckoutReconciliationStore } from "./checkout-reconciliation-store.js";

export type WorkError = CheckoutReconciliationError["code"] | "INTERNAL_ERROR";
type Claim = { eventId: string; leaseToken: string; attemptCount: number };
export type CheckoutEventResult =
  | { state: "idle" }
  | { state: "completed"; observedStatus: "UNPAID" | "PAID" }
  | { state: "deferred" }
  | { state: "retry"; error: WorkError }
  | { state: "lease-lost" };
export type CheckoutEventNotice =
  | Extract<CheckoutEventResult, { state: "retry" | "lease-lost" }>
  | { state: "runner-error" };

export interface CheckoutEventWorkStore {
  claim(businessId: string, connectionId: string, leaseToken: string): Promise<Claim | null>;
  complete(eventId: string, leaseToken: string): Promise<boolean>;
  retry(eventId: string, leaseToken: string, error: WorkError, delaySeconds: number): Promise<boolean>;
}

export class CheckoutEventWorker {
  private readonly reconciler: CheckoutReconciler;

  constructor(
    private readonly work: CheckoutEventWorkStore,
    reconciliation: CheckoutReconciliationStore,
    client: ReconciliationClient,
    private readonly businessId: string,
    private readonly connectionId: string
  ) {
    this.reconciler = new CheckoutReconciler(reconciliation, client, businessId, connectionId);
  }

  async processOne(): Promise<CheckoutEventResult> {
    const claim = await this.work.claim(this.businessId, this.connectionId, randomUUID());
    if (!claim) return { state: "idle" };
    let result: { observedStatus: "UNPAID" | "PAID" };
    try {
      result = await this.reconciler.reconcile(claim.eventId);
    } catch (error) {
      const code: WorkError = error instanceof CheckoutReconciliationError ? error.code : "INTERNAL_ERROR";
      const delay = Math.min(3600, 30 * 2 ** Math.min(claim.attemptCount - 1, 7));
      const retained = await this.work.retry(claim.eventId, claim.leaseToken, code, delay);
      return retained ? { state: "retry", error: code } : { state: "lease-lost" };
    }
    const completed = await this.work.complete(claim.eventId, claim.leaseToken);
    return completed ? { state: "completed", observedStatus: result.observedStatus } : { state: "lease-lost" };
  }
}

export class CheckoutEventRunner {
  private stopped = true;
  private timer?: NodeJS.Timeout;
  private pending?: Promise<void>;

  constructor(
    private readonly worker: Pick<CheckoutEventWorker, "processOne">,
    private readonly report: (notice: CheckoutEventNotice) => void | Promise<void>,
    private readonly unrefTimer = true
  ) {}

  start() {
    if (!this.stopped) return;
    if (this.pending) throw new Error("Checkout event runner is stopping");
    this.stopped = false;
    this.tick();
  }

  async stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    await this.pending;
  }

  private async notify(notice: CheckoutEventNotice) {
    try {
      await this.report(notice);
    } catch {
      console.error("Checkout event worker reporting failed", notice);
    }
  }

  private tick() {
    this.pending = (async () => {
      for (let count = 0; count < 20 && !this.stopped; count++) {
        const result = await this.worker.processOne();
        if (result.state === "idle") break;
        if (result.state === "retry" || result.state === "lease-lost") await this.notify(result);
      }
    })().catch(async () => {
      await this.notify({ state: "runner-error" });
    }).finally(() => {
      this.pending = undefined;
      if (!this.stopped) {
        this.timer = setTimeout(() => this.tick(), 5000);
        if (this.unrefTimer) this.timer.unref();
      }
    });
  }
}
