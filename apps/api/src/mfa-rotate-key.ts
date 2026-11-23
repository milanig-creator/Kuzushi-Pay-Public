import "dotenv/config";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { createDatabase } from "./db.js";
import { rotateMfaKey } from "./mfa-key-rotation.js";

const input = z.object({
  MFA_NEW_KEY: z.string().regex(/^[a-f0-9]{64}$/),
  MFA_ROTATION_CONFIRM: z.literal("rotate")
}).parse(process.env);
const config = loadConfig();
if (config.MFA_ENABLED !== "true" || !config.MFA_KEY) throw new Error("MFA must be enabled with the current key");
if (input.MFA_NEW_KEY === config.SESSION_SECRET || input.MFA_NEW_KEY === config.PASSWORD_RESET_KEY) {
  throw new Error("The new MFA key must be dedicated to MFA");
}
const { prisma, loginRateLimitStore } = createDatabase(config.DATABASE_URL);
try {
  const result = await rotateMfaKey(prisma, config.MFA_KEY, input.MFA_NEW_KEY);
  console.log(`MFA key rotation completed for ${result.count} authenticators.`);
} finally {
  loginRateLimitStore.shutdown();
  await prisma.$disconnect();
}
