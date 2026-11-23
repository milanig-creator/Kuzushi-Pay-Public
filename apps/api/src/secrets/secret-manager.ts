export interface SecretVersion {
  secretId: string;
  version: string;
}

export interface SecretManager {
  addVersion(secretId: string, value: Uint8Array): Promise<SecretVersion>;
  accessVersion(reference: SecretVersion): Promise<Uint8Array>;
  disableVersion(reference: SecretVersion): Promise<void>;
}
