# Reuse an app's password login for assistant connections

**Experimental, unreleased preview.7 API · Node.js 22.6 within 22.x or Node.js 24 · Express 4 · WorkOS development environments.**

Use `createWorkOSPasswordConnection` when an app already has email/password accounts but no browser session for assistant approval. Its routes run on the publisher's backend and origin. Passwords are verified by the publisher's callback there; no Gateivo-hosted account or password service is involved.

```js
import { createWorkOSPasswordConnection } from '@gateivo/sdk/workos-connect/password';

const assistant = createWorkOSPasswordConnection({
  appId: 'your-app', accountName: 'Your app', schemaPrefix: 'your_app_agent',
  publicUrl, issuer, clientId, applicationId, apiKey, accessTokenType,
  secret, pool: yourExistingPgPool,
  requiredScopes: ['setups:read'], actions: [readOwnedSetupAction],
  verifyCredentials: yourAuth.verifyEmailPassword,
  resolveLoginAccount: yourAccounts.findCurrent,
  trustProxyHttps: true, // only behind your explicitly trusted HTTPS proxy
});

// In an explicit deployment task, before enabling the routes:
// await assistant.migrate();
await assistant.ready();
app.use(assistant.router); // before broad body parsers, request logs or a catch-all
```

The variables and `yourAuth`/`yourAccounts` functions are publisher configuration and services, not SDK exports. The constructor does not read environment files, create a pool, migrate schemas, start a server or contact WorkOS. `close()` stops SDK work without closing the publisher's pool.

## Two application hooks

`verifyCredentials({email, password}, {signal})` verifies the existing account password using the app's own password policy and hashing. Return `null` for rejected credentials. `resolveLoginAccount(appSubject, {signal})` re-reads the current eligible account, including disablement and authentication changes.

Both return the same trusted account shape:

```js
{
  appSubject: 'canonical-user-id',
  accountKey: 'immutable-account-creation-id',
  authVersion: 'opaque-current-authentication-revision',
  accountLabel: 'Alice',
  email: 'alice@example.com',
  emailVerified: true,
  enabled: true,
}
```

`appSubject` is the account used by owned service reads. `accountKey` must change when an account is deleted and recreated, even if its email/user ID is reused. `authVersion` must change when the app invalidates password-based browser sessions. Passwords and password hashes must not appear in either identifier. Account keys/revisions are bounded opaque ASCII strings; verified email is ASCII with a dotted domain in this preview. Labels can contain ordinary Unicode text and are escaped in the UI.

These hooks establish identity. Matching an email from a form, tool input, or provider is insufficient. The SDK snapshots and rechecks current account state around session and identity operations, but cannot correct an application callback that reports the wrong account. Honor `signal` and bound database work; an SDK response deadline cannot cancel an application query that ignores cancellation.

## What is packaged

- Browser sign-in/sign-out pages, HTTPS/host checks, CSRF and one-use login state.
- Opaque, short-lived browser sessions, stored as hashes, with durable logout and current-account checks.
- WorkOS Standalone Connect user preparation and browser-bound external-login completion.
- Immutable account/provider bindings and signed external-subject resolution.
- Existing explicit assistant consent, callback, disconnect/reconnect and MCP routing.
- PostgreSQL session, handoff and consent stores using the app's pool, with explicit private-schema migrations.

Signup, password hashing, password reset, social login, account eligibility, subscription rules and owned-data services remain with the application. The password adapter does not reuse a mobile app's signed-in state automatically; an app-to-browser handoff adapter is a separate integration.

## Provider configuration and identity continuity

Use a dedicated WorkOS development environment/client with PKCE, explicit consent and the exact configured read scope. Configure the external sign-in URL as `PUBLIC_URL/account/assistant/external-login`, the app callback as `PUBLIC_URL/account/assistant/callback`, the resource as `PUBLIC_URL/agent/mcp`, and the assistant's callback according to its own documentation. Inspect and explicitly configure the actual signed access-token header profile. See the [WorkOS connection guide](workos-connection.md).

WorkOS provisioning resolves the exact app-derived external ID. Existing users are not discovered or linked by email. An email already assigned to a different provider identity causes the new connection to fail closed. Preserve the session/identity secret and persisted bindings. Moving an existing pilot to this adapter needs a reviewed identity/state migration or isolated test-provider configuration; this preview does not silently import older pilot identities.

The helper currently accepts WorkOS test keys. It is not production authentication acceptance. WorkOS's provider contract is documented in [Standalone Connect](https://workos.com/docs/reference/workos-connect/standalone).

## Routes and lifecycle

Users open `/account/assistant/login`, sign into the app, prepare their connection identity, and separately approve assistant access. Later MCP requests authenticate with assistant tokens, never browser cookies or app passwords. Signing out ends the browser session; explicit Disconnect revokes assistant permission. Reconnecting never revives an earlier revoked consent generation.

Browser sessions require the same `LoginStore` used by this composition. Advanced integrations can use the separate `/login/express`, `/login/postgres` and `/workos-connect/standalone` entries. An existing-session adapter must provide compatible session persistence for atomic handoff validation; an arbitrary `req.user` object is insufficient.

## Local verification

After building, run `npm run test:login`. HTTP/provider fixtures are local simulations; real PostgreSQL checks additionally require the explicit loopback `GATEIVO_LOGIN_TEST_DATABASE_URL` pointing to a disposable `gateivo_login_test` database. They never fall back to `DATABASE_URL`. Fresh hosted WorkOS/Claude acceptance, public HTTPS/proxy verification and production shared login-abuse controls remain deployment checks.
