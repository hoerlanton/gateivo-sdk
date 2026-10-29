# Authentication and application responsibilities

Gateivo exposes application actions to MCP clients. Your application remains responsible for deciding which account a request represents and what that account may do now.

## Two separate permissions

An existing app login establishes the customer's account in your app. A delegated assistant approval grants a particular client a particular scope for a bounded period. A normal mobile login token is not automatically an assistant approval.

For a remote integration, configure an authorization server and an authorization-code flow with PKCE, exact callback addresses, explicit consent and a resource audience matching your MCP endpoint. Set up discovery for the assistant you support. The SDK's protected-resource metadata helper advertises an existing authorization server; it does not implement that server.

## Verify each request

`createAgentRouter` requires a `verifyToken(token, { audience, signal })` callback. It must return a trusted principal or `null` after verifying the delegated credential. Your verification must cover signature, pinned issuer, exact audience/client, expiry, current enabled account, current consent and revocation.

A principal includes the application ID, canonical account subject, approved scopes and expiry. Use the established account binding. Do not derive ownership from an email address or an unverified token decode, and never accept an assistant-supplied owner ID as authority.

The generic registry checks the principal's shape, application, scope and expiry. It cannot infer whether a remote grant was revoked; your verifier and application services supply current access decisions.

## Reuse bounded service functions

An action can call the same service and database layers your mobile API uses. For example:

1. Validate the delegated connection and resolve its account subject.
2. Check that the account and approval remain enabled.
3. Call `readOwnedWorkout(subject, workoutId, { signal })`.
4. Recheck access before returning if a read could overlap revocation.
5. Return a deliberate public projection through an explicit output schema.

Keep database work, pagination and response sizes bounded. SDK timeouts stop waiting; they cannot stop a handler that ignores `AbortSignal` or cancel an unbounded query automatically.

## WorkOS helper

The optional `@gateivo/sdk/workos-connect` entry exports `createWorkOSConnectProvider` and `createWorkOSConnectVerifier`. The root SDK does not require WorkOS.

The adapter supports the inspected signed user-access-token profile and requires exact current consent bindings from your application. Its optional signed-subject resolver maps a verified provider subject to an existing immutable account binding. It must not create account links, approve consent or infer ownership from email.

Provider management resets and consent generations are separate from token signature verification. Persist reset/replacement state, serialize changes and retain revoked generation bindings. Before rollout, verify that disconnect and reconnect keep both old access credentials and old refresh credentials blocked for your exact provider configuration.

The public local example does not configure a real provider. It deliberately uses a loopback-only simulator with temporary in-memory approvals. There is no hosted login, grant database or consent UI in this package.

## Operations

- Keep credentials server-side and outside source control, public issues and logs.
- The optional audit hook contains request/action identifiers, outcome, sanitized error code and duration. It excludes tool payloads and tokens. Delivery is bounded and best effort; connect your own durable sink if required.
- Request concurrency bounds are process-local. Configure shared quotas, monitoring and an action-disable/revocation path for a hosted deployment.
- Use exact host/origin configuration and HTTPS for remote use. Configure trusted proxy behavior deliberately in your hosting application.
- Define narrow read-only service methods. Tool annotations and TypeScript types do not prevent handler side effects.

Subscription enforcement and business entitlements stay with the application. Reusing the SDK does not replace deployment review or provider-specific acceptance.
