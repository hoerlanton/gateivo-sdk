# Call an existing HTTP backend from Gateivo

**Source example · fictional local API · Node.js 22.6 within 22.x or Node.js 24.**
This demonstrates a Gateivo action calling an authenticated, owner-scoped HTTP
API. It is not a Laravel connector, a PHP SDK, a hosted service or a real OAuth
login. The test API is implemented in JavaScript; no PHP or Laravel runtime is
executed by this example.

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

This example does not implement browser sign-in, a Laravel session handoff,
provider-account linking or a production grant store. The normal connection
composition still needs trusted `authenticateSession` and `resolveAccount`
hooks, configured authorization and durable approval state. See the
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
