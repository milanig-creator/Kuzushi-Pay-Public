import type { StripeMode, StripePublication } from "../generated/prisma/client.js";
import type { User } from "../repository.js";

export interface PublicationStore {
  begin(actor: User, businessId: string, draftId: string, mode: StripeMode): Promise<StripePublication | null>;
  find(actor: User, businessId: string, id: string): Promise<StripePublication | null>;
  claimProduct(id: string): Promise<StripePublication | null>;
  recordProduct(id: string, operationId: string, stripeProductId: string): Promise<boolean>;
  claimPrice(id: string): Promise<StripePublication | null>;
  recordPrice(id: string, operationId: string, stripePriceId: string): Promise<boolean>;
}
