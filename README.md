# Gateivo SDK

Expose selected backend functions as scoped tools for AI assistants. Keep your existing accounts, service functions and business rules.

**Experimental developer preview · Node.js / Express 4 · Read-only action interfaces**

This development branch prepares **preview.7**, including optional packaged browser password-login, WorkOS identity handoff and PostgreSQL adapters. They are not in the published `0.1.0-preview.5` archive. For existing password accounts, start with the [packaged login integration](docs/password-login.md); apps with an existing verified browser session can use the [connection guide](docs/workos-connection.md).

[Gateivo website](https://gateivo.com) · [Authentication and responsibilities](docs/authentication.md) · [Report an integration issue](https://github.com/hoerlanton/gateivo-sdk/issues) · [Contact](mailto:anton@gateivo.com)

Gateivo runs in your backend. Your React Native, Flutter or native mobile interface can stay as it is. Claude has been tested with the separate SAGLY staging integration using fictional accounts. This repository's quickstart is a local MCP example, with simulated authorization.

Have an existing Laravel or other HTTP backend? A separate Node adapter can call its authenticated, user-scoped API. The [HTTP-backend source example](https://github.com/hoerlanton/gateivo-sdk/tree/feat/authenticated-reference/examples/http-backend) now includes a Node.js 24 login-to-credential exercise: app password/session, account binding, consent, signed-token verification and the HTTP read. The issuer and API are local fixtures; a real Laravel session integration is still application-specific. Laravel also has a native MCP option; compare the added service and connection-state work before choosing an adapter.

## Make your first tool call

Use **Node.js 22.6+ within 22.x, or Node.js 24.x**, with npm. This preview supports Express 4 and JavaScript or TypeScript.

```sh
# This unreleased branch contains preview.7; the default branch does not.
git clone --branch feat/authenticated-reference https://github.com/hoerlanton/gateivo-sdk.git
cd gateivo-sdk
npm ci
npm run build
npm run demo
```

The demo starts a temporary loopback server and uses the official MCP client to exercise fictional workout actions. It needs no Gateivo account, provider key or customer data. The server shuts down after the exercise.

Read the [workouts example](https://github.com/hoerlanton/gateivo-sdk/tree/main/examples/workouts) to see how existing owner-scoped service functions become tools. Its in-memory approvals are a local simulation; connecting Claude remotely requires real delegated authorization and HTTPS.

## Try an account-linked reference app

For a new email/password integration, `@gateivo/sdk/workos-connect/password` composes the shared login pages, browser sessions, identity handoff, consent and MCP endpoint. The publisher supplies two trusted credential/current-account hooks and owned service actions. The [integration contract](docs/password-login.md) explains the required account creation key, authentication revision, explicit migrations and deployment limits. This is an unreleased, WorkOS-development-only adapter.

The [WorkOS reference app](examples/workos-reference) adds a fictional application login and explicitly configured account mappings around the optional connection module. This fictional host requires **Node.js 24** for its private SQLite store and a separately configured WorkOS development environment. Follow its README to generate private local settings and run it behind an HTTPS reverse proxy.

To integrate with your own existing login, use the [packaged connection module](docs/workos-connection.md): authenticate the app session, then resolve the account's verified provider binding. An optional PostgreSQL adapter uses your app's existing pool. This path supports Node.js 22.6 within 22.x and Node.js 24 without SQLite. The reference app’s own password login is only for its fictional accounts; the separate packaged password adapter is described above.

```sh
# From a built checkout, using Node.js 24:
npm run test:workos
npm run verify:workos
```

These checks use signed synthetic provider responses and an independently installed SDK archive. They verify the local implementation; a fresh hosted WorkOS/Claude connection needs its own acceptance test. The connection module and PostgreSQL adapter enter the runtime archive; the fictional password host, setup generator and SQLite example stay in this repository.

## Define an action using your existing services

```js
import { AccessError, defineAction } from '@gateivo/sdk';
import { z } from 'zod/v4';

// Your application supplies readOwnedWorkout and hasAccess.
export function createWorkoutAction({ readOwnedWorkout, hasAccess }) {
  return defineAction({
    name: 'workouts_get',
    title: 'Read my workout',
    description: 'Read a saved workout from the connected account.',
    requiredScopes: ['workouts:read'],
    inputSchema: z.object({ workoutId: z.string().min(1).max(128) }).strict(),
    outputSchema: z.object({
      workout: z.object({ id: z.string(), title: z.string() }).strict(),
    }).strict(),
    async execute({ workoutId }, { principal, signal }) {
      if (!await hasAccess(principal, signal)) throw new AccessError('FORBIDDEN');
      const row = await readOwnedWorkout(principal.subject, workoutId, { signal });
      if (!row) throw new AccessError('NOT_FOUND');
      if (!await hasAccess(principal, signal)) throw new AccessError('FORBIDDEN');
      return { workout: { id: row.id, title: row.title } };
    },
  });
}
```

`readOwnedWorkout` must enforce ownership and business rules through your existing service/database layer. The assistant supplies the record ID; it does not choose the account whose records it can read.

Mount the actions on your Express application:

```js
import express from 'express';
import { createActionRegistry, createAgentRouter } from '@gateivo/sdk';

const app = express();
const registry = createActionRegistry({
  appId: 'your-app',
  actions: [createWorkoutAction({ readOwnedWorkout, hasAccess })],
});

app.use('/agent/mcp', createAgentRouter({
  registry,
  resource: 'https://api.your-app.example/agent/mcp',
  verifyToken: verifyDelegatedToken, // Implemented by your app.
}));
```

This is an integration outline. Your application supplies the named services and verifier, plus OAuth discovery, consent and deployment configuration. Mount this router before a general body parser, or give that parser equivalent bounds. See the [authentication guide](docs/authentication.md) before exposing it remotely.

## What you reuse, and what your app supplies

| Gateivo SDK | Your application |
| --- | --- |
| Typed action definitions and strict input/output validation | Existing service functions, ownership and business rules |
| App, scope and principal-expiry checks; optional token verifiers | Existing account identity, current entitlements and owner-scoped reads |
| MCP Streamable HTTP transport and protected-resource metadata helpers | Authorization server configuration, HTTPS deployment and verified account linking |
| Optional WorkOS approval/callback/disconnect/reconnect composition and preview password-login adapter | App-owned credential verification or an existing verified session, plus current account and entitlement checks |
| Optional PostgreSQL approval store using your pool | Database hosting, TLS, explicit migrations and preservation of revocation history |
| Request/body limits, timeouts and process-local concurrency bounds | HTTPS hosting, shared quotas and bounded service/database operations |
| Optional best-effort audit hook with outcomes, error codes and timing | Log storage, monitoring, alerts and retention |

The current action API is read-only in intent. Your handlers are ordinary application code: the SDK does not sandbox them or prevent database writes. Keep each exposed service explicitly bounded.

## Public API

| Export | Purpose |
| --- | --- |
| `defineAction` | Define typed tool inputs and public outputs. |
| `createActionRegistry` | Validate principals, permissions, inputs and outputs; apply application policy and limits. |
| `createAgentRouter` | Mount authenticated MCP Streamable HTTP on Express. |
| `createOAuthResource` | Advertise protected-resource metadata for an existing authorization server. |
| `createOAuthJwtVerifier` | Verify the supported RFC 9068 token profile with a required live grant resolver. |
| `AccessError` | Return a deliberate, sanitized application error. |

The root export is provider-neutral. Focused imports are available from `@gateivo/sdk/core`, `/express` and `/oauth`. The optional `/workos-connect` entry supplies a WorkOS HTTP provider and verifier. This branch also includes an unreleased [password login composition](docs/password-login.md), which creates a controlled identity binding after the publisher verifies the user. It still requires durable consent state and deployment-specific lifecycle checks.

The unreleased optional `@gateivo/sdk/workos-connect/express` entry adds `createWorkOSConnection`, which composes approval pages, callbacks, exact consent checks and MCP routing around your existing login. `@gateivo/sdk/workos-connect/postgres` supplies `createWorkOSPostgresStore` with an application-owned pool. Neither entry adds WorkOS, database or hosting accounts automatically. See the [integration guide](docs/workos-connection.md).

### CommonJS on Node.js 22

Use `await import('@gateivo/sdk')` during startup, before accepting requests. The root, OAuth and WorkOS connection entries depend on ESM-only `jose`, so synchronous `require()` of those entries is not supported on Node.js 22.6. Focused `/core` and `/express` entries support synchronous `require()`. Keep one integration on the same import graph so `AccessError` identity stays consistent.

## Installing in another backend

The package name is `@gateivo/sdk`. Install the preview archive in your backend:

```sh
npm install https://github.com/hoerlanton/gateivo-sdk/releases/download/v0.1.0-preview.5/gateivo-sdk-0.1.0-preview.5.tgz
```

There is no public npm registry release yet. To build an archive locally instead:

```sh
# In this repository, after npm ci and npm run build:
npm run pack:preview

# In your own backend, using the archive path reported by that command:
npm install /path/to/the-generated-gateivo-sdk-archive.tgz
```

Preview archives and checksums appear on the [GitHub Releases page](https://github.com/hoerlanton/gateivo-sdk/releases). Each archive must be checked using the clean-consumer verification before release.

## Current scope

- Published archive: `0.1.0-preview.5`. This branch prepares `0.1.0-preview.7`; changes may be required between previews. The existing SAGLY staging deployment remains pinned to its earlier preview.6 candidate.
- Node.js/Express backend integration. There is no frontend or React Native SDK.
- Claude is the tested remote assistant in the separate staging pilot. Other assistants require their own validation.
- No hosted Gateivo account/consent portal, durable log service, billing, automatic subscription enforcement or write-transaction workflow is included.
- Local mock-authorization tests do not establish production OAuth or provider lifecycle correctness.

## Where this could go

We want to learn whether this foundation saves app teams integration work and gives their subscribers a useful new way to access the product. Subscription entitlement adapters, hosted diagnostics, usage insights and more assistant integrations are planned directions, not available services or delivery commitments.

If you try the SDK, tell us what you connected, how far you got and where you got stuck. A completed first call or a concrete integration failure is useful feedback.

- [Open an integration feedback issue](https://github.com/hoerlanton/gateivo-sdk/issues/new/choose)
- [Discuss a publisher pilot](https://gateivo.com/#pilot)
- Email [anton@gateivo.com](mailto:anton@gateivo.com)

## Development

```sh
npm ci
npm run check
npm run demo
```

`check` includes the clean-consumer check, which installs the actual packed SDK in a disposable application outside this checkout. Run it separately with `npm run verify:consumer` when needed. CI is configured for the supported Node.js runtimes. These checks use fictional data and synthetic authorization; they do not log in to WorkOS or Claude.

For maintainers, `npm run verify:release` checks the packed archive against both runtime verification reports and the current distribution/example files. It also requires licence metadata and a licence file. See the contributing guide for the release sequence.

See [the contributing guide](https://github.com/hoerlanton/gateivo-sdk/blob/main/CONTRIBUTING.md) for development notes and [SECURITY.md](SECURITY.md) for vulnerability reports.

## Licence

[MIT](LICENSE) · Copyright (c) 2026 SAGLY GmbH.
