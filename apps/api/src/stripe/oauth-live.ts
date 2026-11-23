import { createHash, createHmac, randomBytes } from "node:crypto";
import type { SessionData } from "express-session";
import { currentUser } from "../authentication.js";
import type { Repository, User } from "../repository.js";
import type { OAuthAttempt } from "./oauth-sandbox.js";
import { exchangeWithStripe, parseStripeOAuthTokens, type StripeOAuthTokens } from "./oauth-sandbox-exchange.js";

type LiveOAuthStatus = "available" | "connected" | "reconnect_required" | "unavailable";

export interface LiveOAuthStore {
  create(attempt: Omit<OAuthAttempt, "environment">): Promise<boolean>;
  consume(stateHash: string, sessionHash: string, actor: User): Promise<string | undefined>;
  status(actor: User, businessId: string): Promise<LiveOAuthStatus>;
  bind(actor: User, businessId: string, tokens: StripeOAuthTokens): Promise<boolean>;
}

const hash = (value: string) => createHash("sha256").update(value).digest("hex");

export class LiveStripeOAuth {
  constructor(private readonly repository: Pick<Repository, "findUserById" | "findBusiness">,
    private readonly store: LiveOAuthStore, private readonly origin: string, private readonly clientId: string,
    private readonly secret: string, private readonly readKey: () => Promise<Uint8Array>,
    private readonly exchange = exchangeWithStripe,
    private readonly externalTest?: { channel: string; businessId: string },
    private readonly publicClientId?: string) {}

  status(actor: User, businessId: string) {
    if (this.externalTest && this.externalTest.businessId !== businessId && !this.publicClientId) return undefined;
    return this.store.status(actor, businessId);
  }

  private sessionHash(id: string) {
    return createHmac("sha256", this.secret).update("stripe-live-oauth:").update(id).digest("hex");
  }

  private async canAuthorize(actor: User, businessId: string) {
    const status = await this.status(actor, businessId);
    return status === "available" || status === "reconnect_required";
  }

  async start(actor: User, sessionId: string, businessId: string) {
    if (actor.role !== "USER" || !await this.repository.findBusiness(actor, businessId) ||
        !await this.canAuthorize(actor, businessId)) return null;
    const state = randomBytes(32).toString("base64url");
    const created = await this.store.create({ id: randomBytes(16).toString("hex"), stateHash: hash(state),
      sessionHash: this.sessionHash(sessionId), userId: actor.id, businessId,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) });
    if (!created) return null;
    const url = new URL("https://marketplace.stripe.com/oauth/v2/authorize");
    const externalTest = this.externalTest?.businessId === businessId ? this.externalTest : undefined;
    if (externalTest) url.pathname = `/oauth/v2/${externalTest.channel}/authorize`;
    url.searchParams.set("client_id", externalTest ? this.clientId : (this.publicClientId ?? this.clientId));
    url.searchParams.set("redirect_uri", `${this.origin}/api/stripe/oauth/live/callback`);
    url.searchParams.set("state", state);
    return url.href;
  }

  async finish(session: Partial<SessionData>, sessionId: string, state: string, code?: string) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(state)) return false;
    const actor = await currentUser(this.repository, session);
    if (!actor || actor.role !== "USER") return false;
    const businessId = await this.store.consume(hash(state), this.sessionHash(sessionId), actor);
    if (!businessId || !code || !/^[A-Za-z0-9_-]{1,2048}$/.test(code)) return false;
    if (!await this.canAuthorize(actor, businessId)) return false;
    const key = Buffer.from(await this.readKey()).toString("utf8");
    if (!/^sk_live_[A-Za-z0-9]+$/.test(key)) return false;
    const response = await this.exchange(key, code);
    const tokens = parseStripeOAuthTokens(response);
    if (!tokens?.livemode || !response || typeof response !== "object" ||
        !("scope" in response) || response.scope !== "stripe_apps") return false;
    return this.store.bind(actor, businessId, tokens);
  }
}
