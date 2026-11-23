import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import session from "express-session";
import express from "express";
import { MemoryStore } from "express-rate-limit";
import request from "supertest";
import { createApp } from "./app.js";
import { hashPassword } from "./security.js";
import { AuthorizationChangedError, EmailInUseError, type Business, type ProductDraft, type Repository, type User } from "./repository.js";
import Stripe from "stripe";
import { SandboxWebhookVerifier } from "./stripe/sandbox-webhook.js";
import { CheckoutWebhookReceiver, type CheckoutWebhookBinding } from "./stripe/checkout-webhook.js";
import { checkoutPilotRouter } from "./stripe/checkout-pilot.js";
import { CheckoutServiceError } from "./stripe/checkout-service.js";
import { LiveStripeOAuth } from "./stripe/oauth-live.js";
import { PublicationError } from "./stripe/publish-product.js";

it.each(["TEST", "LIVE"] as const)("checks access to %s checkout and rejects replay", async (mode) => {
  const storefront = "https://shop.example.com";
  const pilot = express();
  const publishableKey = `pk_${mode.toLowerCase()}_demo`;
  const clientSecret = `cs_${mode.toLowerCase()}_demo_secret_test`;
  const previewToken = "a".repeat(64);
  const requestId = "aa06c8d4-fa22-4bb2-839f-e0a329ebd6ab";
  const create = vi.fn().mockResolvedValueOnce({ clientSecret })
    .mockRejectedValueOnce(new CheckoutServiceError("UNAVAILABLE"));
  pilot.use(express.json(), checkoutPilotRouter({
    origin: storefront, publishableKey, create, mode,
    previewToken: mode === "LIVE" ? previewToken : undefined, rateLimitStore: new MemoryStore()
  }));
  await request(pilot).options("/session").set("Origin", storefront)
    .expect("Access-Control-Allow-Origin", storefront)
    .expect("Access-Control-Allow-Headers", mode === "LIVE" ? "Content-Type, X-Checkout-Preview-Token" : "Content-Type")
    .expect(204);
  await request(pilot).post("/session").set("Origin", "https://elsewhere.example")
    .send({ requestId }).expect(403);
  const checkout = () => request(pilot).post("/session").set("Origin", storefront);
  if (mode === "LIVE") {
    await checkout().send({ requestId }).expect(403);
    await checkout().set("X-Checkout-Preview-Token", "b".repeat(64)).send({ requestId }).expect(403);
  }
  const authorizedCheckout = () => mode === "LIVE" ? checkout().set("X-Checkout-Preview-Token", previewToken) : checkout();
  await authorizedCheckout().send({ requestId, price: "price_override" }).expect(400);
  expect(create).not.toHaveBeenCalled();
  await authorizedCheckout().send({ requestId })
    .expect("Access-Control-Allow-Origin", storefront)
    .expect(201, { clientSecret, publishableKey });
  await authorizedCheckout().send({ requestId }).expect(409);
  expect(create).toHaveBeenCalledWith(requestId);
});

const origin = "http://localhost:5173";
const password = "a-long-test-password";
let hash: string;
let users: User[];
let businesses: Business[];
let memberships: Record<string, string[]>;
let drafts: ProductDraft[];
let app: ReturnType<typeof createApp>;
let repository: Repository;
let healthCheck: () => Promise<void>;
let provisionConflict: boolean;
let loginAuditUnavailable: boolean;
let loginAttempts: { userId: string | null; succeeded: boolean }[];
let beforeUserLookup: () => void;
let draftAuthorizationChanged: boolean;

beforeAll(async () => { hash = await hashPassword(password); });
beforeEach(() => {
  users = [
    { id: "admin", email: "admin@example.com", role: "ADMIN", passwordHash: hash, sessionVersion: 0 },
    { id: "alice", email: "alice@example.com", role: "USER", passwordHash: hash, sessionVersion: 0 },
    { id: "bob", email: "bob@example.com", role: "USER", passwordHash: hash, sessionVersion: 0 }
  ];
  businesses = [{ id: "a", name: "Alice business" }, { id: "b", name: "Bob business" }];
  memberships = { alice: ["a"], bob: ["b"] };
  drafts = [];
  healthCheck = async () => {};
  provisionConflict = false;
  loginAuditUnavailable = false;
  loginAttempts = [];
  beforeUserLookup = () => {};
  draftAuthorizationChanged = false;
  const allowed = (user: User, businessId: string) =>
    businesses.some((business) => business.id === businessId) &&
      (user.role === "ADMIN" || !!memberships[user.id]?.includes(businessId));
  repository = {
    checkHealth: () => healthCheck(),
    findUserByEmail: async (email) => {
      beforeUserLookup();
      return users.find((user) => user.email === email) ?? null;
    },
    findUserById: async (id) => users.find((user) => user.id === id) ?? null,
    hasMfaAuthenticator: async () => false,
    recordLoginAttempt: async (userId, succeeded) => {
      if (loginAuditUnavailable) throw new Error("audit unavailable");
      loginAttempts.push({ userId, succeeded });
    },
    upgradePasswordHash: async (id, previous, next) => {
      const user = users.find((item) => item.id === id && item.passwordHash === previous);
      if (!user) return false;
      user.passwordHash = next;
      return true;
    },
    changePassword: async (id, previous, next) => {
      const user = users.find((item) => item.id === id && item.passwordHash === previous);
      if (!user) return false;
      user.passwordHash = next;
      user.sessionVersion += 1;
      return true;
    },
    listBusinesses: async (user) => businesses.filter((business) => user.role === "ADMIN" || memberships[user.id]?.includes(business.id)),
    findBusiness: async (user, id) => businesses.find((business) => business.id === id && (user.role === "ADMIN" || memberships[user.id]?.includes(id))) ?? null,
    findVerifiedTestCredential: async () => null,
    createBusinessWithOwner: async (_actor, name, email, passwordHash) => {
      if (provisionConflict) throw new EmailInUseError();
      users.push({ id: "new", email, passwordHash, role: "USER", sessionVersion: 0 });
      const business = { id: "new-business", name };
      businesses.push(business);
      memberships.new = [business.id];
      return business;
    },
    listProductDrafts: async (user, businessId) => allowed(user, businessId) ? drafts.filter((draft) => draft.businessId === businessId) : [],
    createProductDraft: async (user, businessId, draft) => {
      if (draftAuthorizationChanged) throw new AuthorizationChangedError();
      if (!allowed(user, businessId)) return null;
      const created = { ...draft, id: `draft-${drafts.length}`, businessId, currency: "USD" as const, createdAt: new Date(), updatedAt: new Date() };
      drafts.push(created);
      return created;
    },
    updateProductDraft: async (user, businessId, id, draft) => {
      const current = drafts.find((item) => item.id === id && item.businessId === businessId);
      if (!current || !allowed(user, businessId)) return null;
      Object.assign(current, draft, { updatedAt: new Date() });
      return current;
    }
  };
  app = createApp({ repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters", origin, production: false });
});

async function login(email: string) {
  const agent = request.agent(app);
  await agent.post("/api/login").set("Origin", origin).send({ email, password }).expect(200);
  return agent;
}

describe("authentication and authorization", () => {
  it("limits live checkout and order history to the owner and returns the session privately", async () => {
    const draftId = "aa06c8d4-fa22-4bb2-839f-e0a329ebd6ab";
    const requestId = "af06c8d4-fa22-4bb2-839f-e0a329ebd6ab";
    const stripeSession = { clientSecret: "checkout_fixture", publishableKey: "pk_live_Fixture123" };
    const create = vi.fn().mockResolvedValue(stripeSession);
    const list = vi.fn().mockResolvedValue([]);
    app = createApp({ repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters",
      origin, production: false, ownerCheckout: { create, list } });
    const orders = "/api/businesses/a/live-orders";
    const path = `/api/businesses/a/product-drafts/${draftId}/checkout`;
    const alice = await login("alice@example.com");
    const bob = await login("bob@example.com");
    await request(app).get(orders).expect(401);
    await bob.get(orders).expect(404);
    await bob.post(path).set("Origin", origin).send({ requestId }).expect(404);
    await alice.post(path).set("Origin", "https://elsewhere.example").send({ requestId }).expect(403);
    await alice.post(path).set("Origin", origin).send({ requestId, price: "price_override" }).expect(400);
    expect(list).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
    await alice.get(orders).expect("Cache-Control", "no-store").expect(200, { orders: [] });
    await alice.post(path).set("Origin", origin).send({ requestId })
      .expect("Cache-Control", "no-store").expect(201, stripeSession);
    expect(list).toHaveBeenCalledWith("a");
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ id: "alice" }), "a", draftId, requestId);
  });
  it("only lets the business owner publish a saved draft and reports uncertain outcomes", async () => {
    const draftId = "aa06c8d4-fa22-4bb2-839f-e0a329ebd6ab";
    const publish = vi.fn().mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new PublicationError("OUTCOME_UNCERTAIN"));
    const list = vi.fn().mockResolvedValue([{ draftId, published: true }]);
    app = createApp({ repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters",
      origin, production: false, livePublication: { publish, list } });
    const draftsPath = "/api/businesses/a/product-drafts";
    const path = `${draftsPath}/${draftId}/publish`;
    const alice = await login("alice@example.com");
    const bob = await login("bob@example.com");
    const admin = await login("admin@example.com");
    await bob.post(path).set("Origin", origin).send({}).expect(404);
    await admin.post(path).set("Origin", origin).send({}).expect(404);
    await alice.post(path).set("Origin", "https://elsewhere.example").send({}).expect(403);
    expect(publish).not.toHaveBeenCalled();
    await alice.post(path).set("Origin", origin).send({}).expect(200, { published: true });
    expect(publish).toHaveBeenCalledWith(expect.objectContaining({ id: "alice" }), "a", draftId);
    await alice.get(draftsPath).expect(200, { drafts: [], publications: [{ draftId, published: true }] });
    await alice.post(path).set("Origin", origin).send({}).expect(409, { error: "PUBLICATION_OUTCOME_UNCERTAIN" });
  });
  it.each([undefined, "ca_publicExample123"])("isolates live Stripe OAuth sessions with public client %s", async (publicClientId) => {
    const actor = users[1];
    let expectedSessionHash: string;
    let pending = true;
    const bind = vi.fn().mockResolvedValue(true);
    const exchange = vi.fn().mockResolvedValue({ access_token: "access", refresh_token: "refresh",
      stripe_user_id: "acct_example", livemode: true, scope: "stripe_apps" });
    const oauth = new LiveStripeOAuth(repository, {
      async create(attempt) { expectedSessionHash = attempt.sessionHash; return true; },
      async consume(_stateHash, sessionHash) {
        if (sessionHash !== expectedSessionHash || !pending) return undefined;
        pending = false;
        return "a";
      },
      async status() { return "available"; }, bind
    }, "https://pay.example.com", "example-client", "example-session-secret",
    async () => Buffer.from("sk_live_example"), exchange, { channel: "chnlink_example_channel", businessId: "a" }, publicClientId);
    memberships.alice.push("b");
    const otherUrl = await oauth.start(actor, "original-session", "b");
    if (publicClientId) {
      expect(new URL(otherUrl!).pathname).toBe("/oauth/v2/authorize");
      expect(new URL(otherUrl!).searchParams.get("client_id")).toBe(publicClientId);
    } else {
      expect(otherUrl).toBeNull();
    }
    const url = new URL((await oauth.start(actor, "original-session", "a"))!);
    expect(url.pathname).toBe("/oauth/v2/chnlink_example_channel/authorize");
    expect(url.searchParams.get("client_id")).toBe("example-client");
    const state = url.searchParams.get("state")!;
    expect(url.searchParams.get("redirect_uri")).toBe("https://pay.example.com/api/stripe/oauth/live/callback");
    const session = { userId: actor.id, authVersion: actor.sessionVersion, authenticatedAt: Date.now() };
    expect(await oauth.finish(session, "different-session", state, "ac_example")).toBe(false);
    expect(exchange).not.toHaveBeenCalled();
    expect(await oauth.finish(session, "original-session", state, "ac_example")).toBe(true);
    expect(bind).toHaveBeenCalledWith(actor, "a", expect.objectContaining({ accountId: "acct_example", livemode: true }));
    expect(await oauth.finish(session, "original-session", state, "ac_example")).toBe(false);
    expect(exchange).toHaveBeenCalledTimes(1);
  });
  it("restricts Stripe Connect links and status to the business owner", async () => {
    const status = vi.fn().mockResolvedValue("pending");
    const start = vi.fn(async (_id: string, stillAuthorized: () => Promise<boolean>) =>
      await stillAuthorized() ? "https://accounts.stripe.com/example" : null);
    app = createApp({ repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters",
      origin, production: false, connectOnboarding: { status, start } });
    const path = "/api/businesses/a/stripe/connect";
    const owner = await login("alice@example.com");
    const other = await login("bob@example.com");
    const admin = await login("admin@example.com");
    await other.get(path).expect(404);
    await admin.post(path).set("Origin", origin).send({}).expect(404);
    await owner.post(path).set("Origin", "https://elsewhere.example").send({}).expect(403);
    expect(status).not.toHaveBeenCalled();
    expect(start).not.toHaveBeenCalled();
    await owner.get(path).expect(200, { status: "pending" });
    await owner.post(path).set("Origin", origin).send({}).expect(200, {
      authorizationUrl: "https://accounts.stripe.com/example"
    });
  });
  it("reports liveness and fails readiness when the database is unavailable", async () => {
    await request(app).get("/health/live").expect(200, { status: "ok" });
    await request(app).get("/health/ready").expect(200, { status: "ok" });
    healthCheck = async () => { throw new Error("database unavailable"); };
    await request(app).get("/health/ready").expect(503, { status: "unavailable" });
    await request(app).get("/health/live").expect(200, { status: "ok" });
  });
  it("allows owners to create and edit only their own valid product drafts", async () => {
    const alice = await login("alice@example.com");
    const bob = await login("bob@example.com");
    const input = {
      name: "  Consultation  ", description: "  Initial session  ", kind: "SERVICE",
      amountCents: 5000, billing: "RECURRING", interval: "MONTH"
    };
    await request(app).get("/api/businesses/a/product-drafts").expect(401);
    await alice.post("/api/businesses/a/product-drafts").set("Origin", "https://evil.example").send(input).expect(403);
    await alice.post("/api/businesses/b/product-drafts").set("Origin", origin).send(input).expect(404);
    for (const invalid of [
      { ...input, amountCents: 0 }, { ...input, amountCents: 1.5 },
      { ...input, interval: null }, { ...input, billing: "ONE_TIME" },
      { ...input, kind: "UNKNOWN" }, { ...input, published: true }
    ]) await alice.post("/api/businesses/a/product-drafts").set("Origin", origin).send(invalid).expect(400);
    const created = await alice.post("/api/businesses/a/product-drafts").set("Origin", origin).send(input).expect(201);
    expect(created.body.draft).toMatchObject({ name: "Consultation", description: "Initial session", billing: "RECURRING" });
    const id = created.body.draft.id;
    await bob.get("/api/businesses/a/product-drafts").expect(404);
    await bob.put(`/api/businesses/a/product-drafts/${id}`).set("Origin", origin).send(input).expect(404);
    await alice.put(`/api/businesses/a/product-drafts/${id}`).set("Origin", origin)
      .send({ ...input, billing: "ONE_TIME", interval: null, amountCents: 2000 }).expect(200);
    expect((await alice.get("/api/businesses/a/product-drafts").expect(200)).body.drafts)
      .toMatchObject([{ id, amountCents: 2000, billing: "ONE_TIME", interval: null }]);
  });
  it("reports session revocation detected during a draft write", async () => {
    const alice = await login("alice@example.com");
    draftAuthorizationChanged = true;
    await alice.post("/api/businesses/a/product-drafts").set("Origin", origin).send({
      name: "Test", description: "", kind: "SERVICE", amountCents: 5000,
      billing: "ONE_TIME", interval: null
    }).expect(401, { error: "UNAUTHENTICATED" });
    expect(drafts).toEqual([]);
  }, 30000);
  it("does not allow public registration or unauthenticated business provisioning", async () => {
    const body = { name: "Test", email: "new@example.com", password };
    await request(app).post("/api/register").set("Origin", origin).send(body).expect(404);
    await request(app).post("/api/signup").set("Origin", origin).send(body).expect(404);
    await request(app).post("/api/businesses").set("Origin", origin).send(body).expect(401);
    expect(users.some((user) => user.email === "new@example.com")).toBe(false);
  });
  it("keeps password recovery unavailable unless explicitly configured", async () => {
    await request(app).get("/api/features").expect(200, { passwordRecovery: false, mfa: false });
    await request(app).post("/api/password-reset/request").set("Origin", origin)
      .send({ email: "alice@example.com", language: "en" }).expect(404);
  });
  it("sends security headers on authentication responses", async () => {
    const response = await request(app).get("/api/me").expect(401);
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["x-frame-options"]).toBe("SAMEORIGIN");
    expect(response.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(response.headers["cache-control"]).toBe("no-store");
    const invalidJson = await request(app).post("/api/login").set("Origin", origin)
      .set("Content-Type", "application/json").send("{").expect(400);
    expect(invalidJson.headers["cache-control"]).toBe("no-store");
  });
  it("requires authentication and rejects bad credentials and cross-origin writes", async () => {
    await request(app).get("/api/businesses").expect(401);
    await request(app).post("/api/login").set("Origin", "https://evil.example").send({ email: "alice@example.com", password }).expect(403);
    await request(app).post("/api/login").set("Origin", origin).send({ email: "alice@example.com", password: "wrong" }).expect(401);
    await request(app).post("/api/login").set("Origin", origin).send({ email: "missing@example.com", password: "wrong" }).expect(401);
    expect(loginAttempts).toEqual([
      { userId: "alice", succeeded: false }, { userId: null, succeeded: false }
    ]);
  });
  it("returns a retryable error when password hashing is at capacity", async () => {
    let ongoing: Promise<string>[] = [];
    beforeUserLookup = () => {
      ongoing = Array.from({ length: 4 }, () => hashPassword(password));
    };
    const logs = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const response = await request(app).post("/api/login").set("Origin", origin)
        .send({ email: "alice@example.com", password }).expect(503);
      expect(response.body).toEqual({ error: "PASSWORD_CAPACITY" });
      expect(response.headers["retry-after"]).toBe("2");
      expect(loginAttempts).toEqual([]);
    } finally {
      await Promise.all(ongoing);
      logs.mockRestore();
    }
  }, 30000);
  it("does not grant a login if recording the successful authentication fails", async () => {
    loginAuditUnavailable = true;
    const agent = request.agent(app);
    await agent.post("/api/login").set("Origin", origin).send({ email: "alice@example.com", password }).expect(500);
    await agent.get("/api/me").expect(401);
  });
  it("limits an owner to their own business, even when changing the ID", async () => {
    const alice = await login("ALICE@example.com");
    const list = await alice.get("/api/businesses").expect(200);
    expect(list.body.businesses).toEqual([{ id: "a", name: "Alice business" }]);
    await alice.get("/api/businesses/a").expect(200);
    await alice.get("/api/businesses/b").expect(404);
    await alice.post("/api/businesses").set("Origin", origin).send({ name: "X", email: "new@example.com", password }).expect(403);
  });
  it("permits administrators to list, inspect and provision businesses", async () => {
    const admin = await login("admin@example.com");
    expect((await admin.get("/api/businesses").expect(200)).body.businesses).toHaveLength(2);
    await admin.get("/api/businesses/b").expect(200);
    await admin.post("/api/businesses").set("Origin", origin).send({ name: "New", email: "new@example.com", password }).expect(201);
    await admin.post("/api/businesses").set("Origin", origin).send({ name: "Other", email: "new@example.com", password }).expect(409);
    await admin.post("/api/businesses").set("Origin", origin).send({ name: "", email: "x", password: "short" }).expect(400);
    const owner = await login("new@example.com");
    expect((await owner.get("/api/businesses").expect(200)).body.businesses).toEqual([{ id: "new-business", name: "New" }]);
  });
  it("reports an email conflict if provisioning loses a concurrent race", async () => {
    const admin = await login("admin@example.com");
    provisionConflict = true;
    await admin.post("/api/businesses").set("Origin", origin)
      .send({ name: "New", email: "racing@example.com", password })
      .expect(409, { error: "EMAIL_IN_USE" });
  });
  it("invalidates the session on logout and blocks originless writes", async () => {
    const alice = await login("alice@example.com");
    await alice.post("/api/logout").send({}).expect(403);
    await alice.post("/api/logout").set("Origin", origin).send({}).expect(200);
    await alice.get("/api/me").expect(401);
  });
  it("changes a password only after verifying the current password and revokes existing sessions", async () => {
    const alice = await login("alice@example.com");
    const anotherSession = await login("alice@example.com");
    const newPassword = "a-different-long-test-password";
    await alice.post("/api/password").set("Origin", origin)
      .send({ currentPassword: "wrong", newPassword }).expect(401);
    await alice.get("/api/me").expect(200);
    await alice.post("/api/password").set("Origin", origin)
      .send({ currentPassword: password, newPassword: password }).expect(400);
    await alice.post("/api/password").set("Origin", origin)
      .send({ currentPassword: password, newPassword }).expect(200);
    await alice.get("/api/me").expect(401);
    await anotherSession.get("/api/me").expect(401);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: "alice@example.com", password }).expect(401);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: "alice@example.com", password: newPassword }).expect(200);
  }, 30000);
  it("rate limits repeated login attempts", async () => {
    const isolatedApp = app;
    for (let n = 0; n < 10; n++) {
      await request(isolatedApp).post("/api/login").set("Origin", origin).send({ email: "alice@example.com", password: "wrong" }).expect(401);
    }
    await request(isolatedApp).post("/api/login").set("Origin", origin).send({ email: "alice@example.com", password }).expect(429);
  }, 30000);
  it("shares the password verification limit between login and password changes", async () => {
    const alice = await login("alice@example.com");
    const input = { currentPassword: "wrong", newPassword: "a-different-long-test-password" };
    for (let n = 0; n < 9; n++) {
      await alice.post("/api/password").set("Origin", origin).send(input).expect(401);
    }
    await alice.post("/api/password").set("Origin", origin).send(input).expect(429);
    await request(app).post("/api/login").set("Origin", origin)
      .send({ email: "alice@example.com", password }).expect(429);
    await alice.get("/api/me").expect(200);
  }, 30000);
});

describe("sandbox webhook boundary", () => {
  it("verifies the raw body without CSRF and never acknowledges unprocessed events", async () => {
    const secret = "whsec_sandboxTestSecret";
    const payload = JSON.stringify({
      id: "evt_test123", object: "event", type: "checkout.session.completed",
      created: 1_700_000_000, livemode: false, account: "acct_expected",
      data: { object: { id: "cs_test_123" } }
    }, null, 2);
    const signature = Stripe.webhooks.generateTestHeaderString({ payload, secret });
    const webhookApp = createApp({
      repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters",
      origin, production: false,
      sandboxWebhook: new SandboxWebhookVerifier({ accountId: "acct_expected", source: "connected" }, [secret])
    });

    await request(app).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "application/json").set("Origin", origin).send(payload).expect(404);
    await request(webhookApp).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "application/json").set("Stripe-Signature", signature)
      .send(payload).expect(503, { error: "WEBHOOK_PROCESSING_UNAVAILABLE" });
    await request(webhookApp).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "application/json").set("Stripe-Signature", signature)
      .send(payload + " ").expect(400, { error: "INVALID_WEBHOOK" });
    await request(webhookApp).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "text/plain").set("Stripe-Signature", signature)
      .send(payload).expect(400, { error: "INVALID_WEBHOOK" });
    await request(webhookApp).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "application/json").set("Content-Encoding", "gzip")
      .set("Stripe-Signature", signature).send(payload).expect(415, { error: "UNSUPPORTED_CONTENT_ENCODING" });
    const maximumPayload = payload + " ".repeat(256 * 1024 - Buffer.byteLength(payload));
    const maximumSignature = Stripe.webhooks.generateTestHeaderString({ payload: maximumPayload, secret });
    await request(webhookApp).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "application/json").set("Stripe-Signature", maximumSignature)
      .send(maximumPayload).expect(503, { error: "WEBHOOK_PROCESSING_UNAVAILABLE" });
    await request(webhookApp).post("/api/stripe/webhooks/sandbox")
      .set("Content-Type", "application/json").send(" ".repeat(256 * 1024 + 1)).expect(413);
    expect(() => createApp({
      repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters",
      origin, production: true,
      sandboxWebhook: new SandboxWebhookVerifier({ accountId: "acct_expected", source: "connected" }, [secret])
    })).toThrow("Sandbox webhooks are unavailable in production");
  });
});

describe("checkout webhook boundary", () => {
  it("acknowledges only verified and durably recorded events", async () => {
    const binding: CheckoutWebhookBinding = {
      connectionId: "1188d7bf-c6d3-4fdb-ae3d-cf7222fe61f6",
      businessId: "d049d2ed-8223-4abd-95e3-a0a85ca8e6e9",
      accountId: "acct_123", mode: "LIVE", source: "direct"
    };
    const secret = "whsec_fixtureSecret";
    const payload = JSON.stringify({
      id: "evt_route", object: "event", type: "checkout.session.completed",
      created: 1_700_000_000, livemode: true,
      data: { object: { id: "cs_live_123", object: "checkout.session" } }
    }, null, 2);
    const signature = Stripe.webhooks.generateTestHeaderString({ payload, secret });
    const bindings = { resolve: vi.fn().mockResolvedValue({ binding, secrets: [secret] }) };
    const eventStore = { record: vi.fn().mockResolvedValueOnce("inserted").mockResolvedValueOnce("duplicate") };
    const webhookApp = createApp({
      repository, store: new session.MemoryStore(), secret: "test-secret-with-at-least-32-characters",
      origin, production: false, checkoutWebhook: new CheckoutWebhookReceiver(bindings, eventStore)
    });
    const path = `/api/stripe/webhooks/checkout/${binding.connectionId}`;
    await request(app).post(path).set("Content-Type", "application/json").set("Origin", origin).send(payload).expect(404);
    for (let count = 0; count < 2; count++) {
      await request(webhookApp).post(path).set("Content-Type", "application/json")
        .set("Stripe-Signature", signature).send(payload).expect(204);
    }
    expect(eventStore.record).toHaveBeenCalledTimes(2);
    await request(webhookApp).post(path).set("Content-Type", "application/json")
      .set("Stripe-Signature", signature).send(payload + " ").expect(400);
    await request(webhookApp).post(path).set("Content-Type", "text/plain")
      .set("Stripe-Signature", signature).send(payload).expect(400);
    await request(webhookApp).post(path).set("Content-Type", "application/json").set("Content-Encoding", "gzip")
      .set("Stripe-Signature", signature).send(payload).expect(415);
    await request(webhookApp).post(path).set("Content-Type", "application/json")
      .send(" ".repeat(256 * 1024 + 1)).expect(413);
    await request(webhookApp).post("/api/stripe/webhooks/checkout/not-a-uuid")
      .set("Content-Type", "application/json").send(payload).expect(400);
    const unsupported = JSON.stringify({
      id: "evt_invoice", object: "event", type: "invoice.paid", created: 1_700_000_000,
      livemode: true, data: { object: { id: "in_123" } }
    });
    await request(webhookApp).post(path).set("Content-Type", "application/json")
      .set("Stripe-Signature", Stripe.webhooks.generateTestHeaderString({ payload: unsupported, secret }))
      .send(unsupported).expect(503);
    bindings.resolve.mockResolvedValueOnce(null);
    await request(webhookApp).post(path).set("Content-Type", "application/json")
      .set("Stripe-Signature", signature).send(payload).expect(503);
    eventStore.record.mockRejectedValueOnce(new Error("private database failure"));
    await request(webhookApp).post(path).set("Content-Type", "application/json")
      .set("Stripe-Signature", signature).send(payload).expect(500);
  });
});
