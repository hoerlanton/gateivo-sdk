# Integrate the account-linked reference with your app

The optional WorkOS reference connects the SDK to an existing application login. Its runnable fictional host demonstrates that composition; your application can replace the host with its existing session and account services.

The reference is source code in `examples/workos-reference/`, separate from the SDK runtime archive. Start with the [runnable app guide](../examples/workos-reference/README.md). It requires Node.js 24 for its private SQLite store. The generic SDK continues to support Node.js 22.6 within 22.x and Node.js 24.

## The identity boundary

An application session identifies a canonical account in your own system. A WorkOS access token identifies a provider user and a consent generation. A trusted, existing binding connects those two identities. The assistant cannot select that binding through a tool argument.

The fictional host uses administrator-configured native WorkOS user IDs for Alice and Bob. It does not register or automatically link real customer accounts. Its generated passwords belong only to the fictional host; they are unrelated to WorkOS login credentials. A hosted test needs both application login and provider approval to complete successfully.

For a publisher integration, keep your existing login and provide two hooks:

```js
import { createWorkOSReference } from './workos-reference/index.mjs';

const assistant = createWorkOSReference({
  appId: 'your-app',
  publicUrl: settings.publicUrl,
  issuer: settings.workosIssuer,
  clientId: settings.assistantClientId,
  applicationId: settings.assistantApplicationId,
  apiKey: secrets.workosTestApiKey,
  accessTokenType: settings.inspectedTokenType,
  requiredScopes: ['workouts:read'],
  secret: secrets.referenceCookieKey, // 32 random bytes, stable across restarts
  store: connectionStore,
  actions: yourOwnerScopedActions,

  async authenticateSession(request, { signal }) {
    const session = await sessions.verifyRequest(request, { signal });
    if (!session) return null;
    return {
      sessionId: session.stableId, // opaque identifier; never the session cookie
      authVersion: session.authVersion,
      appSubject: session.accountId,
      accountLabel: session.displayName,
      expiresAt: session.expiresAt,
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

The `sessions` and `accounts` methods above are illustrative application-owned functions. They are not additional SDK exports. Verify current session validity and account status; do not trust an email match, a decoded unsigned token or an owner ID from a request. Use exact issuer and immutable provider-user bindings.

The optional `resolveTokenSubject` hook can map an already verified signed provider subject to an existing native WorkOS user ID. It is forwarded to both callback exchange and request verification. It must resolve a previously established trusted identity, without creating links or inferring ownership from email. The fictional host uses native provider subjects and does not implement standalone identity provisioning.

## Consent and service calls

The module mounts `/account/assistant`, its start/callback/disconnect routes, `/agent/mcp` and protected-resource metadata. Mount it after your verified session middleware and before a catch-all or an unbounded body parser. Prevent request logs from recording callback queries, cookies, bearer tokens or provider response bodies.

It checks the exact consent generation, resource, client, scopes, deadline and current account mapping. Action wrappers recheck the grant and account around the handler. Your own service functions still enforce ownership, subscription entitlements and business rules, honor cancellation and return bounded public fields.

If your app already owns its MCP router, use `mountMcp: false` and omit `actions`. The returned `verifyToken`, `isAuthorized` and `oauth` hooks compose with that router. Check `isAuthorized` around application reads as well as verifying the delegated token.

## Persistence and reconnect

For one host, `createWorkOSReferenceStore({ path })` from `store.mjs` opens an absolute, private SQLite file. Preserve this file and its revocation history on a persistent private disk. SQLite is unsuitable for an ephemeral application filesystem or multiple app hosts.

For multiple processes or hosts, `createWorkOSPostgresStore({ pool, schema })` in `postgres-store.mjs` accepts an application-owned `pg` pool. Install and configure that dependency in your application; it is not a runtime SDK dependency. Use verified TLS, bounded pool/checkout limits and a dedicated schema. Run `migrate()` explicitly in the deployment process, then `checkReady()` before accepting traffic. Store close does not close the pool. PostgreSQL tests require a separately supplied local test database; the default public checks use SQLite.

Disconnect revokes the local grant. Reconnect creates a new consent generation and retains the old generation's rejection record. A provider reset applies to the entire user/client authorization, so dedicate the client to this reference and serialize its resets through the same durable store. Uncertain provider deletion or token exchange remains blocked across restart. There is no automatic unlock or reset-by-deleting-the-database workflow.

The application page confirms the publisher's approval, rather than the assistant's displayed connection status. After approving in the app, connect or reconnect the connector in the assistant. Disconnecting only in the assistant does not replace this application's local access decision. The module does not claim to remotely revoke every provider refresh token at the moment of local disconnect.

## Provider and assistant setup

Use a dedicated WorkOS development environment and a fixed public third-party OAuth application with PKCE and explicit consent. Configure the application callback, the actual assistant callback, the exact `/agent/mcp` resource and the custom read scope. Set the token header profile explicitly to the inspected supported value. The reference does not dynamically register arbitrary clients.

Scopes restrict the client; user-specific permissions remain an application decision. [WorkOS OAuth applications](https://workos.com/docs/authkit/connect/oauth) and [access-token claims](https://workos.com/docs/authkit/connect/token-claims) describe the provider configuration and token boundary.

Claude's remote connector reaches the application from Anthropic's infrastructure, so a loopback-only server needs a deliberately configured public HTTPS reverse proxy. Use Claude's custom OAuth client setting for the fixed client. Follow its [current connector instructions](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp). Configure proxy trust only for the actual trusted proxy; keep certificate verification enabled.

## What the tests establish

`npm run test:workos` covers the reference's local state, composition and fictional host. `npm run verify:workos` installs an actual SDK archive outside the checkout and exercises HTTP/MCP routes with signed synthetic provider responses and durable SQLite state. No provider key or hosted account is needed by those checks.

A fresh hosted acceptance test is still required for each configured provider/client/resource combination: app login and approval, assistant approval, fresh owned-data read, cross-account denial, disconnect, retained-credential replay, reconnect and rejection of old access/refresh credentials. Record sanitized outcomes and configuration identifiers; keep raw credentials out of evidence. A historical test against another app or an expired pilot is separate evidence.
