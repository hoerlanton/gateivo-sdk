# Existing HTTP backends and a possible Laravel pilot

**Design guide and local HTTP example, not validated Laravel support.** Today's
Gateivo SDK runs in Node.js/Express. Its action handler can call an existing
authenticated HTTP API instead of calling a service in the same process. This
allows a publisher to evaluate a separate Node adapter alongside an existing
backend, without moving its business logic or application database.

The [runnable source example](../examples/http-backend/README.md) tests that HTTP
boundary against a fictional JavaScript server. It does not execute Laravel,
verify a real user's login, or establish hosted assistant/OAuth compatibility.

## First compare the native option

Laravel's current official documentation includes native MCP servers, tools,
authentication and authorization. Its OAuth setup uses Passport, and it also
documents Sanctum/custom authentication. A Laravel team may be able to keep MCP
inside PHP. Node is a requirement of the current Gateivo implementation, not of
MCP itself. See [Laravel MCP authentication](https://laravel.com/framework/docs/13.x/mcp#authentication).

A Gateivo pilot should identify a concrete account-linking, revocation or ongoing
maintenance problem before adding another service. The native option may be a
better fit. This guide does not claim that Gateivo is required or that an adapter
saves time for an application we have not integrated.

## Responsibilities across the boundary

`Claude → Gateivo in Node/Express → authenticated Laravel API`

| Concern | Integration responsibility |
| --- | --- |
| Existing customer sign-in | Laravel or the publisher's existing identity system |
| Verified app session and provider-account binding | Trusted application hooks supplied to Gateivo |
| Assistant token verification, exact approval and disconnect/reconnect | Gateivo's configured connection module and durable store |
| Selecting the backend credential | Trusted server-side lookup for the verified application principal |
| Backend user authentication | Laravel's existing configured API guard |
| Ownership, subscription eligibility and business rules | Laravel services/policies on every read |
| Connection state | The current optional adapter uses PostgreSQL; the Laravel application database need not move |

The adapter adds deployment, configuration and connection-state storage. A local
demo does not establish the total integration or support cost.

## One owned read

The example deliberately has one operation:

```text
GET /api/me/workouts/workout-alice
Authorization: Bearer <existing account-bound backend credential>

200 { "workout": { "id": "workout-alice", "title": "Morning ride" } }
```

The destination origin is fixed server configuration. The model supplies only the
record ID; it supplies no owner, credential, URL, headers or HTTP method. The
upstream backend identifies the current user from its verified credential and
returns only data that user may read. A missing or non-owned record returns the
same `NOT_FOUND` result to the assistant.

The client obtains that backend credential through
`resolveCredential(principal, { signal })`. The publisher supplies this lookup
using its current approved account mapping and credential storage. It does not
issue credentials, understand Laravel session cookies or convert a Claude token
into a Laravel token. Scope the upstream credential to the agreed read, configure
expiry and revocation, and preserve the backend's current eligibility checks.
Do not substitute a global administrator credential with a model-provided user ID.

## Illustrative Laravel endpoint

If the application already uses Sanctum API tokens, an existing route might have
the following shape in `routes/api.php`, assuming the normal `/api` prefix:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->get('/me/workouts/{workoutId}',
    function (Request $request, string $workoutId) {
        abort_unless($request->user()->tokenCan('workouts:read'), 403);
        $workout = $request->user()->workouts()->whereKey($workoutId)->firstOrFail();
        Gate::authorize('view', $workout);

        return response()->json(['workout' => [
            'id' => (string) $workout->getKey(),
            'title' => $workout->title,
        ]]);
    }
);
```

This is an outline for an app that already has the named relationship and view
policy; it has not been run against Laravel. The existing policy must enforce
current eligibility and business rules. Adapt the schema, ID format and guard
to the actual app. Keep any stricter existing controls. Sanctum API-token
authentication and SPA cookie authentication are different flows; the example
does not implement either. See [Sanctum's official guide](https://laravel.com/framework/docs/13.x/sanctum).

## Account login is a separate integration

Gateivo's browser-session hook must verify the existing application session and
return the canonical account, a stable opaque session ID, authentication version
and expiry. Its account hook resolves an existing verified provider binding.
An email comparison or an account ID posted by the browser cannot establish
that binding.

With one public origin, an application-owned reverse proxy can route the login
and connection paths to their respective services, and a trusted server-side
verification hook can ask Laravel to verify its own session. A separate origin
needs an explicit authenticated handoff. Neither forwarding a cookie nor adding
CORS configuration establishes identity by itself. Gateivo does not automatically
decode Laravel cookies or provide that handoff in this example.

Keep the assistant MCP endpoint on bearer-token authentication. Browser login
redirects must not wrap `/agent/mcp` or its public discovery metadata. The
[packaged connection guide](workos-connection.md) describes these existing hooks
and responsibilities; the packaged composition is currently unreleased.

## Qualify one pilot

Before implementing a real adapter, ask which Laravel version and auth flow the
publisher uses, whether an authenticated owner-scoped API exists, which customer
workflow needs assistant access, and whether native Laravel MCP already meets it.

Then agree on one useful read and measure engineering time, required changes,
deployment/storage burden and support interventions. Acceptance should cover a
fresh owned read, other-account denial, expired/disabled accounts, disconnect,
fresh reconnect with old credentials still denied, and sanitized errors. Agree
the observed user benefit and commercial next step separately. These are pilot
criteria, not results established by the local HTTP fixture.
