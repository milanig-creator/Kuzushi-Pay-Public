import "dotenv/config";
import { z } from "zod";
import { createDatabase } from "./db.js";
import { hashPassword } from "./security.js";

const input = z.object({
  DATABASE_URL: z.string().url(),
  BOOTSTRAP_EMAIL: z.string().trim().email().max(254).transform((v) => v.toLowerCase()),
  BOOTSTRAP_PASSWORD: z.string().min(12).max(128).refine(
    (value) => value !== "REPLACE_WITH_A_LONG_UNIQUE_PASSWORD",
    "Replace the example bootstrap password"
  )
}).parse(process.env);
const { prisma } = createDatabase(input.DATABASE_URL);
try {
  const passwordHash = await hashPassword(input.BOOTSTRAP_PASSWORD);
  await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(485723104)`;
    if (await tx.user.count({ where: { role: "ADMIN" } })) {
      throw new Error("An administrator already exists; bootstrap is disabled.");
    }
    const admin = await tx.user.create({ data: { email: input.BOOTSTRAP_EMAIL, passwordHash, role: "ADMIN" } });
    await tx.auditEvent.create({
      data: { actorId: admin.id, action: "ADMIN_BOOTSTRAPPED", targetId: admin.id }
    });
  });
  console.log("Administrator created. Remove bootstrap credentials from your environment.");
} finally {
  await prisma.$disconnect();
}
