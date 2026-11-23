import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import crc32c from "fast-crc32c";
import { GoogleSecretManager, type GoogleSecretApi } from "./google-secret-manager.js";

function fixture() {
  const data = Buffer.from("harmless-test-payload");
  const api: GoogleSecretApi = {
    addVersion: vi.fn().mockResolvedValue({
      name: "projects/123456789/secrets/dev-check/versions/2",
      clientSpecifiedPayloadChecksum: true
    }),
    accessVersion: vi.fn().mockResolvedValue({ data, dataCrc32c: String(crc32c.calculate(data)) }),
    disableVersion: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined)
  };
  return { api, data, manager: new GoogleSecretManager("kuzushi-dev-project", api) };
}

describe("Google Secret Manager provider", () => {
  it("loads the check command in Node and reports missing project configuration", () => {
    const result = spawnSync(process.execPath, [
      "--import", "tsx", fileURLToPath(new URL("./check.ts", import.meta.url))
    ], {
      env: { ...process.env, GOOGLE_SECRET_MANAGER_PROJECT_ID: "" },
      encoding: "utf8"
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Set GOOGLE_SECRET_MANAGER_PROJECT_ID to your development project ID");
  });

  it("adds a version to a pre-created secret with a CRC32C checksum", async () => {
    const { api, manager, data } = fixture();
    expect(await manager.addVersion("dev-check", data)).toEqual({ secretId: "dev-check", version: "2" });
    expect(api.addVersion).toHaveBeenCalledWith(
      "projects/kuzushi-dev-project/secrets/dev-check", data, crc32c.calculate(data)
    );
  });

  it("reads a pinned version, validates integrity and disables only that version", async () => {
    const { api, manager, data } = fixture();
    const reference = { secretId: "dev-check", version: "2" };
    expect(Buffer.from(await manager.accessVersion(reference))).toEqual(data);
    await manager.disableVersion(reference);
    await manager.close();
    expect(api.accessVersion).toHaveBeenCalledWith("projects/kuzushi-dev-project/secrets/dev-check/versions/2");
    expect(api.disableVersion).toHaveBeenCalledWith("projects/kuzushi-dev-project/secrets/dev-check/versions/2");
    expect(api.close).toHaveBeenCalledOnce();
  });

  it("rejects malformed, cross-project and unpinned references before making calls", async () => {
    const { api, manager } = fixture();
    expect(() => new GoogleSecretManager("INVALID/PROJECT", api)).toThrow("Invalid Google Cloud project ID");
    for (const reference of [
      { secretId: "../other", version: "1" },
      { secretId: "projects/other/secrets/x", version: "1" },
      { secretId: "dev-check", version: "latest" },
      { secretId: "dev-check", version: "0" },
      { secretId: "dev-check", version: "1/../../other" }
    ]) {
      await expect(manager.accessVersion(reference)).rejects.toThrow();
      await expect(manager.disableVersion(reference)).rejects.toThrow();
    }
    expect(api.accessVersion).not.toHaveBeenCalled();
    expect(api.disableVersion).not.toHaveBeenCalled();
  });

  it("rejects invalid payload lengths and unconfirmed or unexpected version responses", async () => {
    const { api, manager } = fixture();
    await expect(manager.addVersion("dev-check", new Uint8Array())).rejects.toThrow("1 to 65536");
    await expect(manager.addVersion("dev-check", new Uint8Array(65537))).rejects.toThrow("1 to 65536");
    vi.mocked(api.addVersion).mockResolvedValueOnce({
      name: "projects/123/secrets/other/versions/1",
      clientSpecifiedPayloadChecksum: true
    }).mockResolvedValueOnce({
      name: "projects/123/secrets/dev-check/versions/1",
      clientSpecifiedPayloadChecksum: false
    });
    await expect(manager.addVersion("dev-check", Buffer.from("test"))).rejects.toThrow("response or checksum");
    await expect(manager.addVersion("dev-check", Buffer.from("test"))).rejects.toThrow("response or checksum");
  });

  it("fails closed on missing data, missing checksum and corrupted data", async () => {
    const { api, manager } = fixture();
    vi.mocked(api.accessVersion)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ data: Buffer.from("x") })
      .mockResolvedValueOnce({ data: Buffer.from("x"), dataCrc32c: 0 });
    const ref = { secretId: "dev-check", version: "1" };
    await expect(manager.accessVersion(ref)).rejects.toThrow("missing");
    await expect(manager.accessVersion(ref)).rejects.toThrow("missing");
    await expect(manager.accessVersion(ref)).rejects.toThrow("integrity");
  });

  it("surfaces operation failures without exposing provider messages", async () => {
    const { api, manager } = fixture();
    const error = new Error("sensitive provider detail");
    vi.mocked(api.addVersion).mockRejectedValue(error);
    vi.mocked(api.accessVersion).mockRejectedValue(error);
    vi.mocked(api.disableVersion).mockRejectedValue(error);
    await expect(manager.addVersion("dev-check", Buffer.from("x"))).rejects.toThrow("Failed to add secret version");
    await expect(manager.accessVersion({ secretId: "dev-check", version: "1" })).rejects.toThrow("Failed to access secret version");
    await expect(manager.disableVersion({ secretId: "dev-check", version: "1" })).rejects.toThrow("Failed to disable secret version");
  });

  it("reports safe provider error categories without exposing provider details", async () => {
    const { api, manager } = fixture();
    vi.mocked(api.accessVersion).mockRejectedValue({ code: 7, message: "private details" });
    await expect(manager.accessVersion({ secretId: "dev-check", version: "1" }))
      .rejects.toThrow("Failed to access secret version: permission denied");
  });

  it("rotates pinned versions and rejects access to an obsolete version", async () => {
    const versions = new Map<string, { data: Buffer; enabled: boolean }>();
    let next = 1;
    const api: GoogleSecretApi = {
      addVersion: async (parent, data, checksum) => {
        expect(checksum).toBe(crc32c.calculate(data));
        const version = String(next++);
        versions.set(version, { data: Buffer.from(data), enabled: true });
        return { name: `${parent}/versions/${version}`, clientSpecifiedPayloadChecksum: true };
      },
      accessVersion: async (name) => {
        const entry = versions.get(name.split("/").pop() ?? "");
        if (!entry || !entry.enabled) throw { code: 9 };
        return { data: entry.data, dataCrc32c: crc32c.calculate(entry.data) };
      },
      disableVersion: async (name) => {
        const entry = versions.get(name.split("/").pop() ?? "");
        if (!entry) throw { code: 5 };
        entry.enabled = false;
      },
      close: async () => {}
    };
    const manager = new GoogleSecretManager("kuzushi-dev-project", api);
    const old = await manager.addVersion("dev-check", Buffer.from("test-one"));
    const current = await manager.addVersion("dev-check", Buffer.from("test-two"));
    expect(old.version).toBe("1");
    expect(current.version).toBe("2");
    expect(Buffer.from(await manager.accessVersion(old)).toString()).toBe("test-one");
    expect(Buffer.from(await manager.accessVersion(current)).toString()).toBe("test-two");
    await manager.disableVersion(old);
    await expect(manager.accessVersion(old)).rejects.toThrow("Failed to access secret version");
    expect(Buffer.from(await manager.accessVersion(current)).toString()).toBe("test-two");
  });

  it("does not include secret data or provider details in errors or logs", async () => {
    const { api, manager } = fixture();
    const sensitive = "harmless-sensitive-sentinel";
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      vi.mocked(api.addVersion).mockRejectedValue(new Error(sensitive));
      vi.mocked(api.accessVersion).mockRejectedValue(new Error(sensitive));
      vi.mocked(api.disableVersion).mockRejectedValue(new Error(sensitive));
      for (const operation of [
        () => manager.addVersion("dev-check", Buffer.from(sensitive)),
        () => manager.accessVersion({ secretId: "dev-check", version: "1" }),
        () => manager.disableVersion({ secretId: "dev-check", version: "1" })
      ]) {
        await expect(operation()).rejects.not.toThrow(sensitive);
      }
      expect(log).not.toHaveBeenCalled();
      expect(errorLog).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      errorLog.mockRestore();
    }
  });
});
