import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import crc32c from "fast-crc32c";
import type { SecretManager, SecretVersion } from "./secret-manager.js";

type VersionPayload = { name?: string | null; clientSpecifiedPayloadChecksum?: boolean | null };
type AccessPayload = { data?: Uint8Array | string | null; dataCrc32c?: { toString(): string } | number | string | null };

export interface GoogleSecretApi {
  ensureSecret?(parent: string, secretId: string): Promise<void>;
  addVersion(parent: string, data: Uint8Array, checksum: number): Promise<VersionPayload>;
  accessVersion(name: string): Promise<AccessPayload | null | undefined>;
  disableVersion(name: string): Promise<void>;
  close(): Promise<void>;
}

export class SecretManagerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretManagerError";
  }
}

function failureMessage(action: string, error: unknown): string {
  const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
  const category: Record<number, string> = {
    5: "not found", 7: "permission denied", 8: "quota exceeded",
    16: "authentication failed", 14: "service unavailable"
  };
  const reason = typeof code === "number" ? category[code] : undefined;
  return `Failed to ${action} secret version${reason ? `: ${reason}` : ""}`;
}

export function googleSecretApi(client: SecretManagerServiceClient): GoogleSecretApi {
  return {
    async ensureSecret(parent, secretId) {
      try {
        await client.createSecret({ parent, secretId, secret: { replication: { automatic: {} } } }, { timeout: 5000 });
      } catch (error) {
        if (!(error && typeof error === "object" && "code" in error && error.code === 6)) throw error;
      }
    },
    async addVersion(parent, data, checksum) {
      const [version] = await client.addSecretVersion({ parent, payload: { data, dataCrc32c: checksum } });
      return version;
    },
    async accessVersion(name) {
      const [response] = await client.accessSecretVersion({ name });
      return response.payload;
    },
    async disableVersion(name) {
      await client.disableSecretVersion({ name });
    },
    async close() {
      await client.close();
    }
  };
}

export class GoogleSecretManager implements SecretManager {
  private readonly api: GoogleSecretApi;

  constructor(private readonly projectId: string, api?: GoogleSecretApi) {
    if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
      throw new SecretManagerError("Invalid Google Cloud project ID");
    }
    this.api = api ?? googleSecretApi(new SecretManagerServiceClient());
  }

  private secretName(secretId: string): string {
    if (!/^[a-zA-Z0-9_-]{1,255}$/.test(secretId)) {
      throw new SecretManagerError("Invalid secret ID");
    }
    return `projects/${this.projectId}/secrets/${secretId}`;
  }

  private versionName(reference: SecretVersion): string {
    const parent = this.secretName(reference.secretId);
    if (!/^[1-9][0-9]*$/.test(reference.version)) {
      throw new SecretManagerError("An explicit numeric secret version is required");
    }
    return `${parent}/versions/${reference.version}`;
  }

  async addVersion(secretId: string, value: Uint8Array): Promise<SecretVersion> {
    const parent = this.secretName(secretId);
    if (value.byteLength === 0 || value.byteLength > 65536) {
      throw new SecretManagerError("Secret payload must contain 1 to 65536 bytes");
    }
    const data = Buffer.from(value);
    let response: VersionPayload;
    try {
      response = await this.api.addVersion(parent, data, crc32c.calculate(data));
    } catch (error) {
      throw new SecretManagerError(`${failureMessage("add", error)}; creation outcome may be unknown`);
    }
    const name = response.name?.split("/");
    if (!name || name.length !== 6 || name[0] !== "projects" ||
        !(name[1] === this.projectId || /^[0-9]+$/.test(name[1])) ||
        name[2] !== "secrets" || name[3] !== secretId || name[4] !== "versions" ||
        !/^[1-9][0-9]*$/.test(name[5]) || response.clientSpecifiedPayloadChecksum !== true) {
      throw new SecretManagerError("Secret version response or checksum confirmation is invalid; creation outcome may be unknown");
    }
    return { secretId, version: name[5] };
  }

  async ensureLiveOAuthSecret(secretId: string): Promise<void> {
    if (!/^kp-stripe-oauth-live-[a-f0-9]{32}$/.test(secretId) || !this.api.ensureSecret) {
      throw new SecretManagerError("Invalid live OAuth secret provisioning request");
    }
    try {
      await this.api.ensureSecret(`projects/${this.projectId}`, secretId);
    } catch (error) {
      throw new SecretManagerError(failureMessage("provision", error));
    }
  }

  async accessVersion(reference: SecretVersion): Promise<Uint8Array> {
    const name = this.versionName(reference);
    let payload: AccessPayload | null | undefined;
    try {
      payload = await this.api.accessVersion(name);
    } catch (error) {
      throw new SecretManagerError(failureMessage("access", error));
    }
    if (!payload || !(payload.data instanceof Uint8Array) || payload.dataCrc32c == null) {
      throw new SecretManagerError("Secret payload or checksum is missing");
    }
    const data = Buffer.from(payload.data);
    if (data.length === 0 || data.length > 65536 || String(crc32c.calculate(data)) !== payload.dataCrc32c.toString()) {
      throw new SecretManagerError("Secret payload failed integrity verification");
    }
    return data;
  }

  async disableVersion(reference: SecretVersion): Promise<void> {
    const name = this.versionName(reference);
    try {
      await this.api.disableVersion(name);
    } catch (error) {
      throw new SecretManagerError(failureMessage("disable", error));
    }
  }

  async close(): Promise<void> {
    await this.api.close();
  }
}
