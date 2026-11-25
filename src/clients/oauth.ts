import axios from "axios";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/**
 * OAuth 2.0 authorization-code + refresh-token support for Xero Web apps.
 *
 * Lets the server run against a standard Xero Web app instead of a
 * Custom Connection: a one-time browser login (see auth.ts) stores a
 * refresh token, and the server exchanges it for short-lived access tokens,
 * persisting each rotated refresh token.
 */

export const XERO_AUTHORIZE_URL =
  "https://login.xero.com/identity/connect/authorize";
export const XERO_TOKEN_URL = "https://identity.xero.com/connect/token";
export const XERO_CONNECTIONS_URL = "https://api.xero.com/connections";

/** Granular scopes (same set the Custom Connection client uses) + offline_access for refresh tokens. */
export const DEFAULT_OAUTH_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "accounting.invoices",
  "accounting.payments",
  "accounting.banktransactions",
  "accounting.manualjournals",
  "accounting.reports.aged.read",
  "accounting.reports.balancesheet.read",
  "accounting.reports.profitandloss.read",
  "accounting.reports.trialbalance.read",
  "accounting.contacts",
  "accounting.settings",
  "payroll.settings",
  "payroll.employees",
  "payroll.timesheets",
].join(" ");

/** Refresh this long before the access token actually expires. */
const EXPIRY_MARGIN_MS = 60_000;

export interface XeroConnection {
  tenantId: string;
  tenantName: string;
  tenantType: string;
}

export interface StoredTokens {
  refreshToken: string;
  /** Tenant the server should use unless XERO_TENANT_ID overrides it. */
  tenantId?: string;
  tenantName?: string;
  /** All tenants the user authorised at login. */
  tenants?: XeroConnection[];
  updatedAt: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

export interface AccessToken {
  accessToken: string;
  expiresIn: number;
  tokenType: string;
}

export async function readTokenFile(path: string): Promise<StoredTokens> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    throw new Error(
      `No Xero token file at ${path}. Run the one-time login first: npm run auth`,
    );
  }
  const data = JSON.parse(raw) as StoredTokens;
  if (!data.refreshToken) {
    throw new Error(
      `Token file ${path} has no refreshToken. Re-run: npm run auth`,
    );
  }
  return data;
}

/** Atomic write (temp file + rename) so a crash never leaves a half-written token file. */
export async function writeTokenFile(
  path: string,
  data: StoredTokens,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  await rename(tmp, path);
}

export async function requestToken(
  clientId: string,
  clientSecret: string,
  params: Record<string, string>,
): Promise<TokenResponse> {
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );
  const response = await axios.post<TokenResponse>(
    XERO_TOKEN_URL,
    new URLSearchParams(params).toString(),
    {
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
    },
  );
  return response.data;
}

export async function listConnections(
  accessToken: string,
): Promise<XeroConnection[]> {
  const response = await axios.get<XeroConnection[]>(XERO_CONNECTIONS_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  return response.data ?? [];
}

/**
 * Hands out a valid access token, refreshing via the stored refresh token
 * when needed. Concurrent callers share one in-flight refresh, so a rotated
 * refresh token is never used twice.
 */
export class RefreshTokenManager {
  private current?: AccessToken;
  private expiresAt = 0;
  private inflight?: Promise<AccessToken>;
  private stored?: StoredTokens;

  constructor(
    private readonly options: {
      clientId: string;
      clientSecret: string;
      tokenFile: string;
      now?: () => number;
    },
  ) {}

  private now(): number {
    return this.options.now ? this.options.now() : Date.now();
  }

  /** Tenant recorded at login (after the first refresh has loaded the file). */
  get storedTenantId(): string | undefined {
    return this.stored?.tenantId;
  }

  async getAccessToken(): Promise<AccessToken> {
    if (this.current && this.now() < this.expiresAt - EXPIRY_MARGIN_MS) {
      return this.current;
    }
    if (!this.inflight) {
      this.inflight = this.refresh().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }

  private async refresh(): Promise<AccessToken> {
    const { clientId, clientSecret, tokenFile } = this.options;
    const stored = await readTokenFile(tokenFile);

    let response: TokenResponse;
    try {
      response = await requestToken(clientId, clientSecret, {
        grant_type: "refresh_token",
        refresh_token: stored.refreshToken,
      });
    } catch (error) {
      const data = (error as { response?: { data?: { error?: string } } })
        .response?.data;
      if (data?.error === "invalid_grant") {
        throw new Error(
          "Xero refresh token is expired or revoked (unused for 60 days, or access was removed). Re-run: npm run auth",
        );
      }
      if (typeof data?.error === "string" && /^[a-z_]+$/.test(data.error)) {
        // OAuth error codes (e.g. invalid_client) are safe to surface; never echo the raw response.
        throw new Error(
          `Xero token refresh failed (${data.error}). Check XERO_CLIENT_ID / XERO_CLIENT_SECRET, or re-run: npm run auth`,
        );
      }
      throw error;
    }

    // Persist the rotated refresh token before using the new access token.
    if (
      response.refresh_token &&
      response.refresh_token !== stored.refreshToken
    ) {
      stored.refreshToken = response.refresh_token;
      stored.updatedAt = new Date(this.now()).toISOString();
      await writeTokenFile(tokenFile, stored);
    }

    this.stored = stored;
    this.current = {
      accessToken: response.access_token,
      expiresIn: response.expires_in,
      tokenType: response.token_type,
    };
    this.expiresAt = this.now() + response.expires_in * 1000;
    return this.current;
  }
}
