# Authenticated fictional workout app

This Node.js 24 / Express example adds a runnable app around Gateivo's WorkOS reference. It demonstrates app sign-in, a verified account-to-provider mapping, assistant consent, owner-scoped tools and persistent disconnect/reconnect state.

It uses **fictional app accounts and workout records**. WorkOS and the assistant are real external services when configured. Automated acceptance uses signed synthetic provider responses; it does not establish a successful hosted WorkOS/Claude connection for your configuration.

The password login here is a small fixture for the example. In your own app, keep your existing login and replace the two trusted hooks described below.

## Requirements

- Node.js **24.x**. This example's SQLite store needs Node 24 even though the core SDK also supports Node 22.6+.
- A dedicated WorkOS **development** environment, a third-party OAuth application with PKCE and explicit consent, and the custom `workouts:read` scope assigned to that application.
- Two different native WorkOS users that you control. Complete the provider's required sign-in/verification and confirm each `user_…` ID in the dashboard.
- An HTTPS origin reachable by your chosen assistant, with persistent private storage for this single-host example.

Use a dedicated client for this example. Its reconnect procedure resets that provider user/application authorization; sharing a client with another deployment can disconnect that deployment.

## 1. Configure the development provider

Set up a public third-party OAuth client with authorization-code PKCE and explicit user consent. Use the exact identifiers from its configuration:

| Value | Configure |
| --- | --- |
| App callback | `https://YOUR_REFERENCE_HOST/account/assistant/callback` |
| Resource audience | `https://YOUR_REFERENCE_HOST/agent/mcp` |
| Custom scope | `workouts:read` |
| Assistant callback | The chosen assistant's documented callback. Claude currently documents `https://claude.ai/api/mcp/auth_callback`. |

Both the app approval and assistant connection must use the **same configured OAuth client**. This example does not dynamically register clients.

Inspect the signed **user access token's** header profile in your development environment and select `JWT`, `at+jwt`, or `absent` explicitly. An ID token or normal AuthKit browser-session token is not an assistant access token. Keep tokens out of public logs, issue reports and screenshots.

References: [WorkOS OAuth applications](https://workos.com/docs/authkit/connect/oauth), [WorkOS token claims](https://workos.com/docs/authkit/connect/token-claims), [Claude connector instructions](https://claude.com/docs/connectors/building).

## 2. Create the private app fixture

From the repository root:

```sh
npm ci
npm run build

node examples/workos-reference/setup.mjs \
  --config "$PWD/.gateivo-reference/config.json" \
  --public-url https://YOUR_REFERENCE_HOST \
  --issuer https://YOUR_DEVELOPMENT_ENVIRONMENT.authkit.app \
  --client-id client_YOUR_CLIENT_ID \
  --application-id connect_app_YOUR_APPLICATION_ID \
  --alice-user-id user_VERIFIED_ALICE_ID \
  --bob-user-id user_VERIFIED_BOB_ID \
  --token-type JWT
```

Use your inspected profile for `--token-type`; `at+jwt` and `absent` are also supported. Origins have no trailing slash, path, query or fragment. Use the exact HTTPS address visitors will open.

The command creates a private directory and a `0600` JSON configuration file. It generates independent random app passwords for `alice@gateivo.example` and `bob@gateivo.example`, shows them once in your terminal, and stores only salted scrypt password hashes. It also stores a stable cookie secret. It never overwrites an existing configuration.

**These generated passwords belong only to this fictional app.** They are not passwords for WorkOS, Claude, SAGLY or your email. The command does not create WorkOS users or grant access. The administrator-supplied native user IDs establish the fixture mappings; emails and tool/form arguments never create those mappings.

`.gateivo-reference/` is ignored by Git. Keep it private and back it up together with `connections.sqlite`. Do not commit, share or upload its contents. Run `node examples/workos-reference/setup.mjs --help` for options.

## 3. Start behind HTTPS

The default `loopback-proxy` transport binds only `127.0.0.1:5196`. Run a TLS reverse proxy on the same machine that forwards your public HTTPS origin to that address. It must preserve the exact public `Host` and replace `X-Forwarded-Proto` with `https`, removing any value supplied by the remote visitor. Keep the backend port inaccessible from the network.

Supply `WORKOS_API_KEY` through server-side secret configuration. This runnable host accepts only a development key beginning with `sk_test_`. It never sends the management key to the browser or assistant.

You can use a private root `.env` file based on [the example](.env.example). Set `GATEIVO_REFERENCE_CONFIG` to the absolute path created above and replace the API-key placeholder. Then run:

```sh
node --env-file=.env examples/workos-reference/host.mjs
```

Open the configured **HTTPS public URL**, not the raw loopback HTTP address. The host rejects a wrong `Host`, missing or ambiguous HTTPS forwarding, cross-origin form submissions and oversized login bodies.

For direct TLS, add `--transport tls` during setup and supply `GATEIVO_REFERENCE_TLS_CERT_FILE` and `GATEIVO_REFERENCE_TLS_KEY_FILE` at startup. The private key must be an owner-controlled `0600` file. Direct TLS never falls back to trusting forwarding headers. Use a certificate chain accepted by the remote assistant.

This SQLite example requires a private persistent disk on one host. Do not use an ephemeral Heroku filesystem or share the SQLite file between app hosts. `postgres-store.mjs` is the separate store for application-owned PostgreSQL deployment; migration and pool setup remain explicit application work.

## 4. Approve and connect

1. Sign into this app as `alice@gateivo.example` with **the app password printed by setup**.
2. Open **Manage assistant access** and approve the displayed scope and deadline.
3. On WorkOS's page, sign into **the native WorkOS user mapped to Alice**, using that provider account's own login. Complete consent and return to the app.
4. Add a custom connector in Claude, using `https://YOUR_REFERENCE_HOST/agent/mcp`. Choose your own OAuth client when that option is offered, and use the same client ID configured above. Follow [Claude's current setup instructions](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) if the settings labels differ.
5. Complete Claude's own provider approval. Start a new chat and request a fresh `workouts_list` call.

The account page confirms the app's permission. It cannot confirm whether Claude is connected. The app approval and Claude connection are separate steps.

## What to test

- Alice can list or read `workout-alice-1`; `workout-bob-1` is denied.
- Signing in as Bob uses a different canonical owner and returns Bob's records.
- Disconnect in the app. Fresh assistant calls are denied even if Claude still displays the connector as connected.
- Approve a fresh connection in the app, then reconnect in Claude. If Claude offers only Disconnect/Connect, perform both actions there. Use a new chat to request fresh data rather than relying on an earlier answer.
- Previously issued credentials remain denied after reconnect. For a provider acceptance test, retain old access/refresh credentials only in a controlled verifier and check both families; never paste them into chat or logs.

Browser sign-out ends the app session. It does not revoke an already approved assistant grant; use the explicit **Disconnect** control for that. A new browser login does not restore an old browser cookie or reuse an unfinished approval callback.

The private configuration is re-read during authority checks. Setting an account's `enabled` field to `false`, changing its provider mapping or rotating its password invalidates its browser sessions. A changed or unavailable mapping also denies delegated reads through the reference. Changing server/client/secret settings requires a restart. Preserve existing consent and revocation rows; deleting the database is not a reconnect repair.

## Apply this to your own app

`host.mjs` supplies two trusted application hooks to `createWorkOSReference`:

- `authenticateSession(request, { signal })` verifies the existing app session and returns a canonical account subject, stable non-secret session ID, authentication version, label and expiry.
- `resolveAccount({ issuer, appSubject }, { signal })` checks the currently enabled account and returns its already verified native provider subject. It never infers ownership from email.

Replace the fictional password/session fixtures with your real session and account services. Keep app ownership, subscriptions and other business rules in bounded service functions. The example tools select explicit public fields and include the account owner in every read; the model never selects an owner ID.

The reference enforces live grant/account checks before and after action execution. Read-only annotations do not prevent application handlers from writing, and timeouts cannot cancel business functions that ignore their `AbortSignal`.

The host's browser sessions are process-local and expire after one hour. Restart invalidates those browser sessions; delegated grants and old-generation revocation history remain in the persistent store. The password throttle is intentionally process-local too. Use your existing authentication and shared operational controls for a real customer deployment.

## Automated checks

From the root, use Node.js 24:

```sh
npm run test:workos
npm run verify:workos
```

The independent verifier installs the actual SDK archive outside the checkout and exercises the consent/MCP lifecycle with signed synthetic provider responses. These checks cover implementation behavior, not a completed hosted provider/assistant setup. The fictional host tests cover secure login, CSRF, canonical account binding, disable/rotation, sign-out, private configuration and failure handling.
