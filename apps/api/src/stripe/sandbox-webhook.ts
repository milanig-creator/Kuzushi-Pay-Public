import { z } from "zod";
import { validWebhookSecrets, verifyWebhookSignature } from "./webhook-signature.js";

const eventSchema = z.object({
  id: z.string().regex(/^evt_[A-Za-z0-9]+$/),
  object: z.literal("event"),
  type: z.string().regex(/^[a-z0-9_]+(?:\.[a-z0-9_]+)+$/).max(255),
  created: z.number().int().nonnegative().safe(),
  livemode: z.literal(false),
  account: z.string().regex(/^acct_[A-Za-z0-9]+$/).optional(),
  data: z.object({ object: z.record(z.string(), z.unknown()) })
});

export type SandboxWebhookEndpoint = {
  accountId: string;
  source: "connected" | "direct";
};

export type VerifiedSandboxEvent = {
  id: string;
  type: string;
  created: number;
  accountId: string;
  source: SandboxWebhookEndpoint["source"];
};

export class SandboxWebhookVerifier {
  private readonly endpoint: SandboxWebhookEndpoint;
  private readonly secrets: readonly string[];

  constructor(endpoint: SandboxWebhookEndpoint, secrets: readonly string[]) {
    if (!/^acct_[A-Za-z0-9]+$/.test(endpoint.accountId) ||
        !["connected", "direct"].includes(endpoint.source) ||
        !validWebhookSecrets(secrets)) {
      throw new Error("Invalid sandbox webhook configuration");
    }
    this.endpoint = { ...endpoint };
    this.secrets = [...secrets];
  }

  verify(payload: Buffer, signature: string): VerifiedSandboxEvent | null {
    const raw = verifyWebhookSignature(payload, signature, this.secrets);
    if (!raw) return null;
    const event = eventSchema.safeParse(raw);
    if (!event.success ||
        (this.endpoint.source === "connected" && !event.data.account) ||
        (event.data.account && event.data.account !== this.endpoint.accountId)) return null;
    return {
      id: event.data.id, type: event.data.type, created: event.data.created,
      accountId: this.endpoint.accountId, source: this.endpoint.source
    };
  }
}
