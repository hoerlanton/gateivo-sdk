# Call an existing HTTP backend from Gateivo

**Source examples · Node.js 24 for the full login flow · Node.js 22.6/24 for the HTTP-only flow.**
This demonstrates a Gateivo action calling an authenticated, owner-scoped HTTP
API. The combined login example below connects the existing app-login reference
to that same HTTP boundary. The test API is implemented in JavaScript; no PHP or
Laravel runtime is executed by these examples.

## Start with the verified-login example

Use **Node.js 24** for this example; its reference host uses SQLite. From a fresh
checkout of this development branch:

```sh
git clone --branch feat/authenticated-reference https://github.com/hoerlanton/gateivo-sdk.git
cd gateivo-sdk
npm ci
npm run build
node examples/http-backend/login-demo.mjs
```

The command exercises the full chain with temporary local fixtures:

`Password login → verified app session → account/provider binding → consent and PKCE callback → verified assistant token → account-bound credential lookup → HTTP read`

Password verification, opaque session checks, the SDK's connection flow, signed
token verification, durable grant checks and the actual MCP/HTTP requests run
through their implementations. The identity provider is a signed synthetic
fixture, and the upstream API is a fictional JavaScript server. Local browser
requests simulate the configured same-machine HTTPS proxy; the command does not
contact WorkOS, Claude or Laravel. Passwords, assistant tokens and upstream API
credentials stay in memory. Private temporary configuration and SQLite state
are removed, and the servers close when the exercise ends.

**Review [`authenticated.mjs`](authenticated.mjs) first.** It connects the trusted
application-account resolver to `resolveBackendCredential`, then to the existing
HTTP client's `resolveCredential`. [`login-exercise.mjs`](login-exercise.mjs)
shows the password, session, consent and MCP requests that reach it. The source
login remains the [existing reference host](../workos-reference/host.mjs).

The credential lookup receives a current account snapshot:

```js
{ appId, subject, issuer, providerSubject, authVersion }
```

The publisher-owned lookup returns those same binding fields plus `credential`
and `expiresAt` (Unix milliseconds). The adapter checks the exact binding, account
state, grant and credential expiry around lookup and after the upstream read.
It returns only the credential to the HTTP client. No password, browser cookie,
assistant access token or model-supplied account ID becomes an upstream token.

The lookup is still application-owned. In the exercise, existing fictional API
credentials are provisioned for the two test accounts before sign-in. The flow
proves how a verified identity selects one of those records; it does not issue
credentials for an arbitrary external backend or implement a Laravel session
handoff. Applications retain their current login and credential storage.

Run the focused combined-flow checks on Node.js 24 after building:

```sh
node --test tests/workos-reference-http.test.mjs
```

## Try only the HTTP boundary

From the repository root, after installing its locked dependencies:

```sh
npm ci
npm run build
node examples/http-backend/demo.mjs
node --test examples/http-backend/*.test.mjs
```

The demo creates temporary loopback servers and uses the official MCP client.
It shuts the servers down after checking the boundary. It needs no provider key,
Gateivo account, Laravel installation or customer data. Local approvals and API
credentials are fictional and stay in memory.

## The boundary

`MCP client → Gateivo in Node/Express → existing authenticated backend API`

The action accepts a workout ID. The SDK supplies the verified application
principal. A trusted publisher hook resolves an existing backend credential for
that account. The HTTP client calls only
`GET /api/me/workouts/:workoutId`; the backend resolves the credential's account
and enforces ownership and application permissions. The assistant never selects
an owner, destination URL or backend credential.

The response is projected to `{ workout: { id, title } }`. Private upstream
fields and upstream error bodies are not returned to the assistant. The example
bounds request time and response size, propagates cancellation, rejects
redirects, and uses HTTPS except for the explicitly enabled loopback fixture.

## Files and integration points

- `authenticated.mjs`: the verified account-to-credential composition to review first.
- `login-exercise.mjs`, `login-demo.mjs`: the combined login/consent/MCP exercise.
- `login-provider-fixture.mjs`: the signed local provider simulation used by that exercise.
- `actions.mjs`: the strict tool input and public output, plus one action.
- `client.mjs`: the bounded HTTP call and trusted `resolveCredential` hook.
- `index.mjs`: composition with the existing SDK registry and Express router.
- `fixture.mjs`: the local fictional API; do not deploy it as authentication.
- `demo.mjs` and the test files: the local exercise and boundary checks.

These helpers are source examples, not new `@gateivo/sdk` exports. Reuse and
adapt them inside your application. Your actual record IDs, response fields,
permissions and API paths must match your application's service contract.

## What the publisher still supplies

The `resolveCredential(principal, { signal })` hook must look up a credential
already bound to the exact approved application account. It must return `null`
when that account cannot use the upstream API. It must honor cancellation and
avoid logging its credential. Credential issuance, encrypted storage, rotation,
scope, expiry and user authorization remain application responsibilities. Use
an account-bound read credential with explicit expiry and revocation; this
client does not reduce the privileges of an overly broad API token. A shared
administrator token plus an unverified user-ID header is not this pattern.

The smaller `demo.mjs` uses simulated approvals and credential selection. The
combined `login-demo.mjs` supplies the fictional app sign-in, configured provider
bindings and SQLite approval store. A real application still supplies its
`authenticateSession` and `resolveAccount` hooks, provider configuration, backend
credentials and production storage. Laravel session handoff remains
application-specific. See the
[existing-app connection guide](../../docs/workos-connection.md).

The assistant's OAuth access token and the backend's user credential are separate
credentials for separate recipients. Do not forward the assistant token to an
API that is not its intended resource. Do not put an upstream credential in tool
arguments, public outputs, URLs, prompts or log events.

## Considering Laravel

Read the [HTTP-backend and Laravel pilot guide](../../docs/http-backends.md).
Laravel has a native MCP implementation too; a Node adapter is one way to
evaluate today's Gateivo SDK, not a requirement imposed by MCP. Choose the
integration after comparing its operational work with the app's existing stack.
