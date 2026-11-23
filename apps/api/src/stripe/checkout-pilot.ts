import { createHash, timingSafeEqual } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { rateLimit, type Store } from "express-rate-limit";
import { z } from "zod";
import { CheckoutServiceError } from "./checkout-service.js";

const requestSchema = z.object({ requestId: z.uuid() }).strict();
const previewTokenHeader = "X-Checkout-Preview-Token";
const digestToken = (token: string) => createHash("sha256").update(token).digest();

export function checkoutPilotRouter(pilot: {
  origin: string;
  publishableKey: string;
  rateLimitStore: Store;
  mode?: "LIVE" | "TEST";
  previewToken?: string;
  create(requestId: string): Promise<{ clientSecret: string; publishableKey?: string }>;
}) {
  const router = Router();
  const live = pilot.mode === "LIVE";
  const previewTokenDigest = pilot.previewToken ? digestToken(pilot.previewToken) : undefined;
  const requirePreviewToken: RequestHandler = (req, res, next) => {
    const token = req.get(previewTokenHeader);
    if (live && (!token || !previewTokenDigest || !timingSafeEqual(digestToken(token), previewTokenDigest))) {
      res.status(403).json({ error: "FORBIDDEN" });
      return;
    }
    next();
  };
  const allowOrigin: RequestHandler = (req, res, next) => {
    res.vary("Origin");
    if (req.get("origin") !== pilot.origin) {
      res.status(403).json({ error: "FORBIDDEN_ORIGIN" });
      return;
    }
    res.set("Access-Control-Allow-Origin", pilot.origin);
    next();
  };
  router.options("/session", allowOrigin, (_req, res) => {
    res.set({
      "Access-Control-Allow-Methods": "POST",
      "Access-Control-Allow-Headers": live ? `Content-Type, ${previewTokenHeader}` : "Content-Type"
    });
    res.sendStatus(204);
  });
  router.post("/session", allowOrigin, requirePreviewToken, rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    keyGenerator: () => pilot.mode === "LIVE" ? "checkout-live:global" : "checkout-pilot:global",
    store: pilot.rateLimitStore,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) => { res.status(429).json({ error: "RATE_LIMITED" }); }
  }), async (req, res) => {
    const parsed = requestSchema.safeParse(req.body);
    if (!req.is("application/json") || !parsed.success) {
      res.status(400).json({ error: "INVALID_INPUT" });
      return;
    }
    try {
      const { clientSecret, publishableKey = pilot.publishableKey } = await pilot.create(parsed.data.requestId);
      res.status(201).json({ clientSecret, publishableKey });
    } catch (error) {
      if (error instanceof CheckoutServiceError && error.code === "UNAVAILABLE") {
        res.status(409).json({ error: "CHECKOUT_UNAVAILABLE" });
        return;
      }
      console.error(`Checkout ${pilot.mode === "LIVE" ? "live" : "pilot"} session unavailable`);
      res.status(503).json({ error: "CHECKOUT_UNAVAILABLE" });
    }
  });
  return router;
}
