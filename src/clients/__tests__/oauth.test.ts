import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import axios from "axios";

import { RefreshTokenManager, writeTokenFile } from "../oauth.js";

vi.mock("axios");
const post = vi.mocked(axios.post);

function tokenReply(access: string, refresh: string, expiresIn = 1800) {
  return {
    data: {
      access_token: access,
      refresh_token: refresh,
      expires_in: expiresIn,
      token_type: "Bearer",
    },
  };
}

describe("RefreshTokenManager", () => {
  let dir: string;
  let tokenFile: string;
  let clock: number;

  const manager = () =>
    new RefreshTokenManager({
      clientId: "id",
      clientSecret: "secret",
      tokenFile,
      now: () => clock,
    });

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "xero-oauth-"));
    tokenFile = join(dir, "tokens.json");
    clock = 1_000_000;
    post.mockReset();
    await writeTokenFile(tokenFile, {
      refreshToken: "refresh-1",
      tenantId: "tenant-a",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("refreshes, persists the rotated refresh token and exposes the stored tenant", async () => {
    post.mockResolvedValueOnce(tokenReply("access-1", "refresh-2"));
    const m = manager();

    const token = await m.getAccessToken();

    expect(token.accessToken).toBe("access-1");
    expect(post.mock.calls[0][1]).toContain("refresh_token=refresh-1");
    const saved = JSON.parse(await readFile(tokenFile, "utf8"));
    expect(saved.refreshToken).toBe("refresh-2");
    expect(saved.tenantId).toBe("tenant-a");
    expect(m.storedTenantId).toBe("tenant-a");
    expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("reuses the access token until shortly before expiry", async () => {
    post
      .mockResolvedValueOnce(tokenReply("access-1", "refresh-2"))
      .mockResolvedValueOnce(tokenReply("access-2", "refresh-3"));
    const m = manager();

    await m.getAccessToken();
    clock += 25 * 60_000; // 25 of 30 minutes
    expect((await m.getAccessToken()).accessToken).toBe("access-1");
    expect(post).toHaveBeenCalledTimes(1);

    clock += 4.5 * 60_000; // inside the 60s safety margin
    expect((await m.getAccessToken()).accessToken).toBe("access-2");
    expect(post.mock.calls[1][1]).toContain("refresh_token=refresh-2");
  });

  it("shares one refresh between concurrent callers", async () => {
    post.mockResolvedValueOnce(tokenReply("access-1", "refresh-2"));
    const m = manager();

    const results = await Promise.all([
      m.getAccessToken(),
      m.getAccessToken(),
      m.getAccessToken(),
    ]);

    expect(post).toHaveBeenCalledTimes(1);
    expect(results.map((r) => r.accessToken)).toEqual([
      "access-1",
      "access-1",
      "access-1",
    ]);
  });

  it("explains how to recover from an expired refresh token", async () => {
    post.mockRejectedValueOnce({
      response: { status: 400, data: { error: "invalid_grant" } },
    });

    await expect(manager().getAccessToken()).rejects.toThrow(/npm run auth/);
  });

  it("names the OAuth error code for bad client credentials", async () => {
    post.mockRejectedValueOnce({
      response: { status: 400, data: { error: "invalid_client" } },
    });

    await expect(manager().getAccessToken()).rejects.toThrow(
      /refresh failed \(invalid_client\)/,
    );
    const saved = JSON.parse(await readFile(tokenFile, "utf8"));
    expect(saved.refreshToken).toBe("refresh-1");
  });

  it("explains how to log in when the token file is missing", async () => {
    await rm(tokenFile);

    await expect(manager().getAccessToken()).rejects.toThrow(/npm run auth/);
    expect(post).not.toHaveBeenCalled();
  });
});
