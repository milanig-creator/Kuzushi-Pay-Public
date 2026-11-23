import { createHash, createHmac, randomBytes } from "node:crypto";
import type { SessionData } from "express-session";
import { currentUser } from "../authentication.js";
import type { Repository } from "../repository.js";

export type OAuthAttempt = {
  id: string;
  stateHash: string;
  sessionHash: string;
  userId: string;
  businessId: string;
  environment: "SANDBOX";
  expiresAt: Date;
};

export interface OAuthAttemptStore {
  create(attempt: OAuthAttempt): Promise<boolean>;
  consume(stateHash: string, sessionHash: string, userId: string, now: Date, businessId?: string): Promise<boolean>;
}

export type SandboxOAuthConfig = { installUrl: string; redirectUri: string; businessId?: string };

export function validateSandboxOAuthConfig(config: SandboxOAuthConfig): void {
  const install = new URL(config.installUrl);
  const redirect = new URL(config.redirectUri);
  const redirectUris = install.searchParams.getAll("redirect_uri");
  if (install.protocol !== "https:" || install.hostname !== "marketplace.stripe.com" ||
      install.port || install.username || install.password || install.hash ||
      (install.pathname !== "/oauth/v2/authorize" &&
        !/^\/oauth\/v2\/[A-Za-z0-9_-]{40}\/authorize$/.test(install.pathname)) ||
      install.searchParams.getAll("client_id").length !== 1 ||
      !install.searchParams.get("client_id") || install.searchParams.has("state") ||
      redirectUris.length > 1 || (redirectUris.length === 1 && redirectUris[0] !== config.redirectUri)) {
    throw new Error("Invalid Stripe sandbox external test URL");
  }
  if (redirect.protocol !== "https:" || redirect.username || redirect.password ||
      redirect.search || redirect.hash || redirect.pathname !== "/api/stripe/oauth/sandbox/callback") {
    throw new Error("Invalid Stripe sandbox HTTPS callback URI");
  }
}

const hash = (value: string) => createHash("sha256").update(value).digest("hex");

export class SandboxOAuthService {
  constructor(
    private readonly repository: Pick<Repository, "findUserById" | "findBusiness">,
    private readonly attempts: OAuthAttemptStore,
    private readonly config: SandboxOAuthConfig,
    private readonly secret: string
  ) { validateSandboxOAuthConfig(config); }

  isEnabledForBusiness(businessId: string): boolean {
    return !this.config.businessId || this.config.businessId === businessId;
  }

  private sessionHash(sessionId: string): string {
    return createHmac("sha256", this.secret).update("stripe-oauth-session:").update(sessionId).digest("hex");
  }

  async initiate(session: Partial<SessionData>, sessionId: string, businessId: string) {
    const user = await currentUser(this.repository, session);
    if (!user) return { error: "UNAUTHENTICATED" } as const;
    if (!this.isEnabledForBusiness(businessId)) return { error: "NOT_FOUND" } as const;
    if (!await this.repository.findBusiness(user, businessId)) return { error: "NOT_FOUND" } as const;
    const state = randomBytes(32).toString("base64url");
    const created = await this.attempts.create({
      id: randomBytes(16).toString("hex"), stateHash: hash(state),
      sessionHash: this.sessionHash(sessionId), userId: user.id, businessId,
      environment: "SANDBOX", expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });
    if (!created) return { error: "AUTHORIZATION_IN_PROGRESS" } as const;
    const url = new URL(this.config.installUrl);
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("state", state);
    return { url: url.toString() } as const;
  }

  async callback(session: Partial<SessionData>, sessionId: string, state: string): Promise<boolean> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(state)) return false;
    const user = await currentUser(this.repository, session);
    if (!user) return false;
    return this.attempts.consume(hash(state), this.sessionHash(sessionId), user.id, new Date(), this.config.businessId);
  }
}
