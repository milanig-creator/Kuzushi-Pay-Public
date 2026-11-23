import { z } from "zod";
import { validWebhookSecrets, verifyWebhookSignature } from "./webhook-signature.js";

const eventSchema = z.object({
  id: z.string().regex(/^evt_[A-Za-z0-9]+$/),
  object: z.literal("event"),
  type: z.string().regex(/^[a-z0-9_]+(?:\.[a-z0-9_]+)+$/).max(255),
  created: z.number().int().nonnegative().safe(),
  livemode: z.boolean(),
  account: z.string().regex(/^acct_[A-Za-z0-9]+$/).optional(),
  data: z.object({ object: z.record(z.string(), z.unknown()) })
});
const sessionEventTypes = [
  "checkout.session.completed", "checkout.session.async_payment_succeeded",
  "checkout.session.async_payment_failed", "checkout.session.expired"
] as const;
const sessionEventTypeSchema = z.enum(sessionEventTypes);
const bindingSchema = z.object({
  connectionId: z.string().uuid(),
  businessId: z.string().uuid(),
  accountId: z.string().regex(/^acct_[A-Za-z0-9]+$/),
  mode: z.enum(["TEST", "LIVE"]),
  source: z.enum(["direct", "connected"])
}).strict();

export type CheckoutWebhookBinding = z.output<typeof bindingSchema>;
export type VerifiedCheckoutEvent = {
  id: string;
  type: z.output<typeof sessionEventTypeSchema>;
  sessionId: string;
  created: number;
};
export interface CheckoutWebhookStore {
  record(binding: CheckoutWebhookBinding, event: VerifiedCheckoutEvent): Promise<"inserted" | "duplicate">;
}

export interface CheckoutWebhookBindings {
  resolve(connectionId: string): Promise<{ binding: CheckoutWebhookBinding; secrets: readonly string[] } | null>;
}

export class CheckoutWebhookInbox {
  private readonly binding: CheckoutWebhookBinding;
  private readonly secrets: readonly string[];

  constructor(binding: CheckoutWebhookBinding, secrets: readonly string[], private readonly store: CheckoutWebhookStore) {
    const parsed = bindingSchema.safeParse(binding);
    if (!parsed.success || !validWebhookSecrets(secrets)) throw new Error("Invalid checkout webhook configuration");
    this.binding = parsed.data;
    this.secrets = [...secrets];
  }

  async accept(payload: Buffer, signature: string): Promise<"invalid" | "ignored" | "inserted" | "duplicate"> {
    const raw = verifyWebhookSignature(payload, signature, this.secrets);
    if (!raw) return "invalid";
    const event = eventSchema.safeParse(raw);
    if (!event.success || event.data.livemode !== (this.binding.mode === "LIVE") ||
        (this.binding.source === "connected" && !event.data.account) ||
        (event.data.account && event.data.account !== this.binding.accountId)) return "invalid";
    const type = sessionEventTypeSchema.safeParse(event.data.type);
    if (!type.success) return "ignored";
    const session = z.object({
      id: z.string().regex(this.binding.mode === "LIVE" ? /^cs_live_[A-Za-z0-9]+$/ : /^cs_test_[A-Za-z0-9]+$/),
      object: z.literal("checkout.session")
    }).safeParse(event.data.data.object);
    if (!session.success) return "invalid";
    return this.store.record(this.binding, {
      id: event.data.id, type: type.data, sessionId: session.data.id, created: event.data.created
    });
  }
}

export class CheckoutWebhookReceiver {
  constructor(private readonly bindings: CheckoutWebhookBindings, private readonly store: CheckoutWebhookStore) {}

  async accept(
    connectionId: string, payload: Buffer, signature: string
  ): Promise<"invalid" | "ignored" | "inserted" | "duplicate" | "unavailable"> {
    if (!z.string().uuid().safeParse(connectionId).success || !Buffer.isBuffer(payload) ||
        payload.length === 0 || payload.length > 256 * 1024 || !signature || signature.length > 4096) return "invalid";
    const resolved = await this.bindings.resolve(connectionId);
    if (!resolved) return "unavailable";
    if (resolved.binding.connectionId !== connectionId) throw new Error("Checkout webhook binding mismatch");
    return new CheckoutWebhookInbox(resolved.binding, resolved.secrets, this.store).accept(payload, signature);
  }
}
