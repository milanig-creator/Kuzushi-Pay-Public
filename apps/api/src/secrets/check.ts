import { GoogleSecretManager } from "./google-secret-manager.js";

const projectId = process.env.GOOGLE_SECRET_MANAGER_PROJECT_ID;
if (!projectId) throw new Error("Set GOOGLE_SECRET_MANAGER_PROJECT_ID to your development project ID");

const manager = new GoogleSecretManager(projectId);
try {
  const value = await manager.accessVersion({ secretId: "kuzushi-pay-dev-check", version: "1" });
  if (!Buffer.from(value).equals(Buffer.from("kuzushi-pay-secret-manager-check-v1", "utf8"))) {
    throw new Error("Test secret does not match the expected harmless value");
  }
  console.log("Development Secret Manager access verified.");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Secret Manager check failed");
  process.exitCode = 1;
} finally {
  await manager.close();
}
