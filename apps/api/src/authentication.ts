import type { SessionData } from "express-session";
import type { Repository, User } from "./repository.js";

const sessionLifetimeMs = 8 * 60 * 60 * 1000;

export async function currentUser(repository: Pick<Repository, "findUserById">, data: Partial<SessionData>): Promise<User | null> {
  if (typeof data.authenticatedAt !== "number" || typeof data.authVersion !== "number") return null;
  const age = Date.now() - data.authenticatedAt;
  if (!data.userId || !Number.isFinite(age) || age < 0 || age >= sessionLifetimeMs) return null;
  const user = await repository.findUserById(data.userId);
  return user?.sessionVersion === data.authVersion ? user : null;
}

export { sessionLifetimeMs };
