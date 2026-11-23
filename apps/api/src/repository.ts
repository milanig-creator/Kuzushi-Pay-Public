export type User = { id: string; email: string; passwordHash: string; role: "ADMIN" | "USER"; sessionVersion: number };
export type Business = { id: string; name: string };
export type CredentialReference = { secretId: string; version: string };
export class EmailInUseError extends Error {
  constructor() { super("Email is already in use"); }
}
export class AuthorizationChangedError extends Error {
  constructor() { super("Authorization changed"); }
}
export type ProductDraftInput = {
  name: string;
  description: string;
  kind: "PHYSICAL" | "DIGITAL" | "SERVICE";
  amountCents: number;
  billing: "ONE_TIME" | "RECURRING";
  interval: "DAY" | "WEEK" | "MONTH" | "YEAR" | null;
};
export type ProductDraft = ProductDraftInput & {
  id: string; businessId: string; currency: "USD"; createdAt: Date; updatedAt: Date
};
export interface Repository {
  checkHealth(): Promise<void>;
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  hasMfaAuthenticator(id: string): Promise<boolean>;
  recordLoginAttempt(userId: string | null, succeeded: boolean): Promise<void>;
  upgradePasswordHash(id: string, previousHash: string, newHash: string): Promise<boolean>;
  changePassword(id: string, previousHash: string, newHash: string): Promise<boolean>;
  listBusinesses(user: User): Promise<Business[]>;
  findBusiness(user: User, id: string): Promise<Business | null>;
  findVerifiedTestCredential(user: User, businessId: string): Promise<CredentialReference | null>;
  createBusinessWithOwner(actor: User, name: string, email: string, passwordHash: string): Promise<Business>;
  listProductDrafts(user: User, businessId: string): Promise<ProductDraft[]>;
  createProductDraft(user: User, businessId: string, draft: ProductDraftInput): Promise<ProductDraft | null>;
  updateProductDraft(user: User, businessId: string, id: string, draft: ProductDraftInput): Promise<ProductDraft | null>;
}
