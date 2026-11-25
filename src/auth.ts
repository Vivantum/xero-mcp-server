#!/usr/bin/env node
/**
 * One-time interactive login for a Xero Web app (OAuth 2.0 authorization code).
 *
 *   XERO_CLIENT_ID, XERO_CLIENT_SECRET, XERO_TOKEN_FILE   required
 *   XERO_REDIRECT_URI   default http://localhost:49831/callback (must match the app)
 *   XERO_SCOPES         default DEFAULT_OAUTH_SCOPES
 *   XERO_TENANT_ID      optional: which authorised organisation to use
 *
 * Opens the Xero consent page, captures the code on a loopback-only callback,
 * and saves the refresh token + connected organisations to XERO_TOKEN_FILE.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import dotenv from "dotenv";

import {
  DEFAULT_OAUTH_SCOPES,
  listConnections,
  requestToken,
  writeTokenFile,
  XERO_AUTHORIZE_URL,
} from "./clients/oauth.js";

dotenv.config();

const LOGIN_TIMEOUT_MS = 5 * 60_000;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`${name} is not set.`);
    process.exit(1);
  }
  return value;
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
}

function openBrowser(url: string): void {
  const [cmd, args] =
    process.platform === "win32"
      ? ["explorer.exe", [url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  spawn(cmd, args, { stdio: "ignore", detached: true })
    .on("error", () => {})
    .unref();
}

async function main(): Promise<void> {
  const clientId = requireEnv("XERO_CLIENT_ID");
  const clientSecret = requireEnv("XERO_CLIENT_SECRET");
  const tokenFile = requireEnv("XERO_TOKEN_FILE");
  const redirectUri =
    process.env.XERO_REDIRECT_URI ?? "http://localhost:49831/callback";
  const scopes = process.env.XERO_SCOPES ?? DEFAULT_OAUTH_SCOPES;
  const wantedTenant = process.env.XERO_TENANT_ID;

  const redirect = new URL(redirectUri);
  if (!["localhost", "127.0.0.1"].includes(redirect.hostname)) {
    throw new Error("XERO_REDIRECT_URI must point at localhost.");
  }
  const port = Number(redirect.port || 80);
  const state = randomBytes(32).toString("hex");

  const consentUrl = `${XERO_AUTHORIZE_URL}?${new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    state,
  })}`;

  const servers: Server[] = [];
  const closeAll = () => servers.forEach((s) => s.close());

  const result = new Promise<string>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("Timed out waiting for the Xero login.")),
      LOGIN_TIMEOUT_MS,
    );

    const handler: Parameters<typeof createServer>[1] = async (req, res) => {
      const url = new URL(req.url ?? "/", redirectUri);
      if (url.pathname !== redirect.pathname) {
        res.writeHead(404).end();
        return;
      }
      const fail = (message: string) => {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<h2>Xero login failed</h2><p>${escapeHtml(message)}</p>`);
        clearTimeout(timer);
        reject(new Error(message));
      };

      if (url.searchParams.get("state") !== state) {
        return fail("State mismatch - ignoring this callback.");
      }
      const error = url.searchParams.get("error");
      if (error) return fail(`Xero returned: ${error}`);
      const code = url.searchParams.get("code");
      if (!code) return fail("No authorization code in callback.");

      try {
        const token = await requestToken(clientId, clientSecret, {
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
        });
        if (!token.refresh_token) {
          return fail(
            "No refresh token returned - is offline_access in the scopes?",
          );
        }

        const tenants = (await listConnections(token.access_token)).filter(
          (t) => t.tenantType === "ORGANISATION",
        );
        if (!tenants.length)
          return fail("No Xero organisation was authorised.");

        const chosen = wantedTenant
          ? tenants.find((t) => t.tenantId === wantedTenant)
          : tenants[0];
        if (!chosen) {
          return fail(
            `XERO_TENANT_ID ${wantedTenant} was not among the authorised organisations.`,
          );
        }

        await writeTokenFile(tokenFile, {
          refreshToken: token.refresh_token,
          tenantId: chosen.tenantId,
          tenantName: chosen.tenantName,
          tenants,
          updatedAt: new Date().toISOString(),
        });

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          `<h2>Xero connected</h2><p>Using <b>${escapeHtml(chosen.tenantName)}</b>. You can close this tab.</p>`,
        );

        console.log(`\nSaved refresh token to ${tokenFile}`);
        console.log("Authorised organisations:");
        for (const t of tenants) {
          console.log(
            `  ${t.tenantId === chosen.tenantId ? "*" : " "} ${t.tenantName}  ${t.tenantId}`,
          );
        }
        if (tenants.length > 1) {
          console.log(
            "\nSet XERO_TENANT_ID and re-run to use a different organisation.",
          );
        }
        clearTimeout(timer);
        resolve(chosen.tenantId);
      } catch (err) {
        fail((err as Error).message);
      }
    };

    // Loopback only: listen on IPv4 and (if available) IPv6, never on the LAN.
    for (const host of ["127.0.0.1", "::1"]) {
      const server = createServer(handler);
      server.on("error", (err: NodeJS.ErrnoException) => {
        if (host === "::1") return; // no IPv6 loopback on this machine - IPv4 is enough
        clearTimeout(timer);
        reject(err);
      });
      server.listen(port, host);
      servers.push(server);
    }
  });

  console.log(`Waiting for the Xero callback on ${redirectUri}`);
  console.log("If the browser doesn't open, visit:\n");
  console.log(consentUrl + "\n");
  openBrowser(consentUrl);

  try {
    await result;
  } finally {
    closeAll();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("Error:", (err as Error).message);
    process.exit(1);
  },
);
