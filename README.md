# Kuzushi Pay

A full-stack payments dashboard I built for storefront operators. It connects a merchant's Stripe account, publishes products and prices, opens embedded Checkout, and reconciles payment status back to the merchant's dashboard.

## What I built

- **Merchant onboarding.** A Stripe OAuth flow ties authorization to the signed-in owner and business. The backend stores versioned credential references in PostgreSQL and keeps OAuth tokens in Google Secret Manager.
- **Product publishing.** Owners turn drafts into Stripe products and prices. The backend records an immutable publication snapshot, claims each Stripe write once, and surfaces uncertain outcomes for investigation.
- **Embedded Checkout.** Signed-in owners preview a published product directly in the dashboard. The app records the Stripe session and queues recovery before returning the Checkout client secret.
- **Payment reconciliation.** A background worker leases due jobs, checks Stripe's current session and line-item state, and updates the initial payment status idempotently. I verified a controlled live purchase that produced a paid order with quantity one.
- **Tenant controls.** The app includes business-scoped access, PostgreSQL-backed rate limits, and audit events for sensitive state changes.

## Stack

React, TypeScript, Express, PostgreSQL, Prisma, Stripe, Google Secret Manager, and Vitest. The live service is deployed on Render.

## Explore the code

| Area | Location |
| --- | --- |
| Merchant dashboard | [apps/web/src](apps/web/src) |
| OAuth, publishing, and checkout | [apps/api/src/stripe](apps/api/src/stripe) |
| Data model and migrations | [prisma](prisma) |

## Run locally

Use Node.js 22.12+ (22.x) or 24+, npm, and Docker Compose.

1. Copy `.env.example` to `.env`. Set matching local PostgreSQL passwords in `POSTGRES_PASSWORD` and `DATABASE_URL`, plus a unique `SESSION_SECRET` and bootstrap password.
2. Run `docker compose up -d`, then `npm ci`, `npm run generate`, `npm run migrate:deploy`, and `npm run bootstrap`.
3. Run `npm run dev:api` and `npm run dev:web` in separate terminals. Open http://localhost:5173 and sign in with the bootstrap credentials.
4. Run `npm test` for the unit suite and `npm run build` for the production build.

This portfolio snapshot uses example environment settings. The local dashboard can run without Stripe credentials. Payment testing needs a separately configured Stripe test environment.
