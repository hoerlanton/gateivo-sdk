# Add assistant connections to an existing Express app

**Unreleased development API.** These optional imports are being prepared for the next preview archive. The published `0.1.0-preview.5` archive does not include them. Build and install an archive from this branch to evaluate them; this is not an npm registry release.

```js
import { createWorkOSConnection } from '@gateivo/sdk/workos-connect/express';
import { createWorkOSPostgresStore } from '@gateivo/sdk/workos-connect/postgres';
```

This composition supplies the approval page, OAuth start/callback handling, exact consent checks, disconnect/reconnect state machine and authenticated MCP routing. Your app keeps its current login, accounts and owner-scoped services. It runs on the SDK's supported Node.js 22.6 within 22.x and Node.js 24 runtimes; the separate fictional SQLite host requires Node.js 24.

## Evaluate this development version

```sh
git clone --branch feat/authenticated-reference https://github.com/hoerlanton/gateivo-sdk.git
cd gateivo-sdk
npm ci
npm run pack:preview

# In your own backend, use the absolute path to the archive just built:
npm install /absolute/path/gateivo-sdk/artifacts/gateivo-sdk-0.1.0-preview.6.tgz
```

The development branch must contain this change before those commands can retrieve it. The archive contains the connection module and its declarations; copying `examples/workos-reference/` into your backend is unnecessary. Your app supplies and configures `pg` if it uses the PostgreSQL adapter.

## What the app connects

Provide two trusted hooks:

1. `authenticateSession` verifies the existing application session and returns its canonical account ID, stable session ID, authentication version and expiry. Return `null` when the session is no longer valid.
2. `resolveAccount` looks up the enabled account and its previously verified provider-user binding for the exact configured issuer. Return `null` when the binding is missing or disabled.

These hooks read current application state. An email match or a tool argument cannot establish an account binding. This module does not provision WorkOS accounts or automatically link customers.

## Store and migration

Use your existing application-owned `pg` pool. The adapter checks clients out of that pool; it does not install the driver, create its own pool, change your pool settings, or close the pool when the store closes.

```js
const connections = createWorkOSPostgresStore({
  pool: yourExistingPgPool,
  schema: 'gateivo_connections',
});
```

Run `await connections.migrate()` in an explicit deployment/release task. It creates the adapter's dedicated schema and verifies its marker and shape; it rejects unrelated schemas. Call `await connections.checkReady()` before the web app accepts traffic. Configure verified database TLS, bounded pool checkout/capacity and pool error handling in your application. Preserve the schema and old revocation records across deployments.

## Connect the existing services

This example assumes that `settings`, `secrets`, `sessions`, `accounts`, `setups` and `yourExistingPgPool` already belong to your application. Their methods are illustrative application code, not extra SDK exports. A previously configured WorkOS development client and verified account binding are required.

```js
import { AccessError, defineAction } from '@gateivo/sdk';
import { createWorkOSConnection } from '@gateivo/sdk/workos-connect/express';
import { createWorkOSPostgresStore } from '@gateivo/sdk/workos-connect/postgres';
import { z } from 'zod/v4';

const connections = createWorkOSPostgresStore({
  pool: yourExistingPgPool,
  schema: 'gateivo_connections',
});
await connections.checkReady(); // migrate separately in the release task

const readSetup = defineAction({
  name: 'setups_get',
  title: 'Read my setup',
  description: 'Read a saved setup from the connected account.',
  requiredScopes: ['setups:read'],
  inputSchema: z.object({ setupId: z.string().min(1).max(128) }).strict(),
  outputSchema: z.object({
    setup: z.object({ id: z.string(), name: z.string() }).strict(),
  }).strict(),
  async execute({ setupId }, { principal, signal }) {
    const row = await setups.getOwned(principal.subject, setupId, { signal });
    if (!row) throw new AccessError('NOT_FOUND');
    return { setup: { id: row.id, name: row.name } };
  },
});

const assistant = createWorkOSConnection({
  appId: 'your-app',
  publicUrl: settings.publicUrl,
  issuer: settings.workosIssuer,
  clientId: settings.assistantClientId,
  applicationId: settings.assistantApplicationId,
  apiKey: secrets.workosApiKey,
  accessTokenType: settings.inspectedTokenType,
  requiredScopes: ['setups:read'],
  secret: secrets.connectionCookieKey, // 32 random bytes, stable across restarts
  store: connections,
  actions: [readSetup],

  async authenticateSession(request, { signal }) {
    const session = await sessions.verifyRequest(request, { signal });
    if (!session) return null;
    return {
      sessionId: session.stableId, // opaque, at most 256 characters; not a cookie
      authVersion: session.authVersion, // opaque, at most 256 characters
      appSubject: session.accountId,
      accountLabel: session.displayName,
      expiresAt: session.expiresAt, // Unix milliseconds
    };
  },

  async resolveAccount({ issuer, appSubject }, { signal }) {
    const account = await accounts.findEnabled(appSubject, { signal });
    if (!account) return null;
    const binding = await accounts.findVerifiedProviderBinding(account.id, issuer, { signal });
    return binding ? { providerSubject: binding.providerUserId, enabled: true } : null;
  },
});

app.use(assistant.router);
```

Mount at the app root, after any existing verified session middleware and before a catch-all or unbounded body parser. The module owns `/account/assistant` and its child routes, `/agent/mcp` and protected-resource metadata. Configure HTTPS and proxy trust for the actual hosting setup. An optional audit hook emits bounded, sanitized outcomes; your app supplies log storage and monitoring.

Keep browser-login redirects limited to the account pages: `/agent/mcp` authenticates the assistant's bearer token, and protected-resource metadata is public. Do not put either behind middleware that requires a browser session. Your application directs signed-out users to its existing login; the connection module returns 401 when its browser session hook cannot authenticate the request.

For callback troubleshooting, the optional second argument accepts `onConsentDiagnostic(event)`. It reports only the fixed operation, failure phase and sanitized reason; it excludes tokens, identities and provider/error details. The payload is read-only, and observer failures do not change the callback response or durable fencing. Your application supplies the logging sink; this is separate from the action audit hook and is not a hosted log service.

The connection module rechecks the exact approved account and grant before and after each action. Your service still enforces ownership, subscription entitlements and business rules, honors cancellation, and bounds database work. Neither tool annotations nor timeouts prevent a handler from writing data or continuing work if it ignores cancellation.

## Approval and reconnect

An application login proves the customer's app account. A separate provider approval gives the configured assistant client bounded read access. Configure the exact application callback, assistant callback, resource URL and custom scope in WorkOS. Existing configuration requirements are detailed in the [provider/reference guide](workos-reference.md#provider-and-assistant-setup).

Disconnect revokes local access. Reconnect obtains a new consent generation; it does not revive a revoked generation. Provider resets apply to the whole provider-user/client authorization, so dedicate the client to this integration and use the same durable store for its lifecycle. Uncertain reset or code-exchange outcomes remain blocked for operator review.

The app page confirms local account approval. A user then connects or reconnects the service in the assistant's settings. The page cannot assert the assistant's remote connection status. Local disconnect does not promise immediate deletion of every provider refresh token.

## Existing MCP router

With `mountMcp: false`, omit `actions` and compose the returned `verifyToken`, `isAuthorized` and `oauth` with an existing MCP router. Recheck `isAuthorized` around application reads. The default composition mounts and wraps the actions for you.

## Verification scope

The installed-archive tests use fictional accounts and signed synthetic provider responses. PostgreSQL acceptance uses an explicitly selected disposable loopback database and checks restart/concurrency behavior. A fresh hosted provider and assistant acceptance test remains necessary for your own issuer/client/resource configuration. The SAGLY staging pilot is separate evidence for its deployed preview.5 integration; it does not establish a hosted acceptance result for this new archive.
