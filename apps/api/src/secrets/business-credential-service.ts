import type { SessionData } from "express-session";
import { currentUser } from "../authentication.js";
import type { Repository } from "../repository.js";
import type { SecretManager } from "./secret-manager.js";

export class CredentialAccessError extends Error {
  constructor() {
    super("Credential unavailable");
    this.name = "CredentialAccessError";
  }
}

export class BusinessCredentialService {
  constructor(
    private readonly repository: Pick<Repository, "findUserById" | "findVerifiedTestCredential">,
    private readonly secrets: SecretManager
  ) {}

  async accessTestCredential(session: Partial<SessionData>, businessId: string): Promise<Uint8Array> {
    const user = await currentUser(this.repository, session);
    if (!user) throw new CredentialAccessError();
    const reference = await this.repository.findVerifiedTestCredential(user, businessId);
    if (!reference || !/^kp-stripe-test-[0-9a-f]{32}$/.test(reference.secretId) ||
        !/^[1-9][0-9]*$/.test(reference.version)) {
      throw new CredentialAccessError();
    }
    return this.secrets.accessVersion(reference);
  }
}
