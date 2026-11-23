import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { z } from "zod";
import type { User } from "../repository.js";
import { validCheckoutReturnUrl } from "./embedded-checkout.js";

const proposalSchema = z.object({
  origin: z.string().min(1).max(2048),
  returnUrl: z.string().min(1).max(2048)
}).strict().refine(({ origin, returnUrl }) =>
  !/[\u0000-\u0020\u007f]/.test(origin + returnUrl) && validCheckoutReturnUrl(origin, returnUrl)
);

export type StorefrontProposalInput = z.input<typeof proposalSchema>;
export type StorefrontProposal = StorefrontProposalInput & {
  businessId: string; revision: string; createdAt: Date; updatedAt: Date; verifiedAt: Date | null;
  testApprovedAt: Date | null;
};
export interface StorefrontProposalStore {
  find(actor: User, businessId: string): Promise<StorefrontProposal | null>;
  save(actor: User, businessId: string, proposal: StorefrontProposalInput): Promise<StorefrontProposal | null>;
  verify(actor: User, businessId: string, revision: string): Promise<StorefrontProposal | null>;
  approveTest(actor: User, businessId: string, revision: string): Promise<StorefrontProposal | null>;
}

function storefrontDnsHostname(value: string) {
  const origin = URL.parse(value);
  if (!origin) return null;
  const hostname = origin.hostname;
  if (origin.port || hostname.length > 240 || isIP(hostname) ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(hostname)) {
    return null;
  }
  return hostname;
}

export const storefrontSetupSchema = proposalSchema.refine(({ origin }) => !!storefrontDnsHostname(origin));

export function storefrontDnsChallenge(proposal: StorefrontProposal) {
  const hostname = storefrontDnsHostname(proposal.origin);
  return hostname ? {
    name: `_kuzushi-pay.${hostname}.`, value: `kuzushi-pay-verification=${proposal.revision}`
  } : null;
}

export async function hasStorefrontDnsProof(
  proposal: StorefrontProposal,
  resolveTxt = (name: string) => new Resolver({ timeout: 2000, tries: 1 }).resolveTxt(name)
): Promise<boolean> {
  const challenge = storefrontDnsChallenge(proposal);
  if (!challenge) return false;
  try {
    const records = await resolveTxt(challenge.name);
    return records.some((chunks) => chunks.join("") === challenge.value);
  } catch {
    return false;
  }
}

export function parseStorefrontProposal(value: StorefrontProposalInput): StorefrontProposalInput {
  const parsed = proposalSchema.safeParse(value);
  if (!parsed.success) throw new Error("Invalid storefront proposal");
  return parsed.data;
}
