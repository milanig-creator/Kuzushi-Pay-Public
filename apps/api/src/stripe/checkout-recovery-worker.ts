import { randomUUID } from "node:crypto";
import {
  CheckoutReconciler, CheckoutReconciliationError, type ReconciliationSource
} from "./checkout-reconciler.js";
import type { CheckoutEventResult, WorkError } from "./checkout-event-worker.js";
import type { CheckoutReconciliationStore } from "./checkout-reconciliation-store.js";

type Claim = { attemptId: string; leaseToken: string; attemptCount: number; alreadyPaid: boolean };
export interface CheckoutRecoveryWorkStore {
  claim(businessId: string, connectionId: string, leaseToken: string): Promise<Claim | null>;
  complete(attemptId: string, leaseToken: string): Promise<boolean>;
  retry(attemptId: string, leaseToken: string, error: WorkError | null, delaySeconds: number): Promise<boolean>;
}

export class CheckoutRecoveryWorker {
  private readonly reconciler: CheckoutReconciler;

  constructor(
    private readonly work: CheckoutRecoveryWorkStore,
    reconciliation: CheckoutReconciliationStore,
    client: ReconciliationSource,
    private readonly businessId: string,
    private readonly connectionId: string
  ) {
    this.reconciler = new CheckoutReconciler(reconciliation, client, businessId, connectionId);
  }

  async processOne(): Promise<CheckoutEventResult> {
    const claim = await this.work.claim(this.businessId, this.connectionId, randomUUID());
    if (!claim) return { state: "idle" };
    if (claim.alreadyPaid) {
      return await this.work.complete(claim.attemptId, claim.leaseToken)
        ? { state: "completed", observedStatus: "PAID" } : { state: "lease-lost" };
    }

    let result: Awaited<ReturnType<CheckoutReconciler["reconcileAttempt"]>>;
    try {
      result = await this.reconciler.reconcileAttempt(claim.attemptId);
    } catch (error) {
      const code: WorkError = error instanceof CheckoutReconciliationError ? error.code : "INTERNAL_ERROR";
      const delay = Math.min(3600, 30 * 2 ** Math.min(claim.attemptCount - 1, 7));
      const retained = await this.work.retry(claim.attemptId, claim.leaseToken, code, delay);
      return retained ? { state: "retry", error: code } : { state: "lease-lost" };
    }
    if (result.observedStatus === "PAID" || result.sessionStatus === "expired") {
      return await this.work.complete(claim.attemptId, claim.leaseToken)
        ? { state: "completed", observedStatus: result.observedStatus } : { state: "lease-lost" };
    }
    const delay = Math.min(3600, 300 * 2 ** Math.min(claim.attemptCount - 1, 4));
    const retained = await this.work.retry(claim.attemptId, claim.leaseToken, null, delay);
    return retained ? { state: "deferred" } : { state: "lease-lost" };
  }
}
