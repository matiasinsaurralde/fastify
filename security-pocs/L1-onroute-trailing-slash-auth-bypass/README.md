# L1 — Authorization bypass via the `onRoute`-invisible trailing-slash twin

| | |
|---|---|
| **Severity** | **MEDIUM-HIGH** (conditional on `onRoute`-based security controls) |
| **Class** | Authorization bypass / inconsistent route bookkeeping |
| **CWE** | CWE-289 (Authentication Bypass by Alternate Name), CWE-863 (Incorrect Authorization) |
| **Component** | `lib/route.js` (route registration + `onRoute` dispatch) — Fastify core |
| **Auth required** | No |
| **Affected** | `fastify@5.10.0` |

## Summary

When a route is declared at path `/` **inside a plugin that has a non-empty
prefix**, Fastify's default `prefixTrailingSlash: 'both'` registers **two**
independently routable paths — `/prefix` and `/prefix/` — but fires the
`onRoute` hook for **only the first**. The trailing-slash twin `/prefix/` runs
the exact same handler yet is never announced to `onRoute`.

Any security or governance control that discovers routes by subscribing to
`onRoute` — RBAC/authorization registries, API gateways, rate-limiters, WAF
policy generators, CSRF-exemption lists, audit tooling — is therefore **blind to
`/prefix/`**. An attacker reaches the protected handler unauthenticated simply by
appending a `/`.

## Attacker model & preconditions

- Remote client, no authentication.
- Precondition (app side), both common:
  1. A route registered at `/` inside a plugin mounted under a `prefix`
     (e.g. `fastify.register(admin, { prefix: '/admin' })` where `admin`
     declares `instance.get('/', …)`) — the standard way to give a mounted
     sub-app an index route.
  2. A security control that determines which routes exist / need protection by
     listening to `onRoute` (a widespread RBAC / gateway pattern).
- `ignoreTrailingSlash: true`, in-scope `addHook`, and route-level hooks all
  correctly protect the twin — so this specifically bites the
  onRoute-enumeration style of control.

## Root-cause analysis

`lib/route.js` — for a `/` route under a prefix, the `'both'` (default) branch
registers the no-slash form normally and the slash form with `prefixing: true`:

```js
// lib/route.js  (prepareRoute)
if (path === '/' && prefix.length > 0 && opts.method !== 'HEAD') {
  switch (opts.prefixTrailingSlash) {
    // …
    case 'both':
    default:
      addNewRoute.call(this, { path: '', isFastify })                 // -> "/prefix"  (prefixing:false)
      if (ignoreTrailingSlash !== true && /* … */) {
        addNewRoute.call(this, { path, prefixing: true, isFastify })  // -> "/prefix/" (prefixing:TRUE)
      }
  }
}
```

`addNewRoute` fires the `onRoute` hooks **only when `prefixing === false`**:

```js
// lib/route.js  (addNewRoute)
if (prefixing === false) {
  // run 'onRoute' hooks
  for (const hook of this[kHooks].onRoute) {
    hook.call(this, opts)
  }
}
```

So `/prefix/` is added to the router (fully routable, same handler/context) but
its `onRoute` event is suppressed. The suppression was presumably meant to avoid
announcing "the same" index route twice — but the two paths are independently
matchable, so a route-aware security layer ends up with an entry for `/prefix`
and none for `/prefix/`.

(Notably, the auto-generated **HEAD** twin *is* announced as
`HEAD:/prefix/`, which makes the missing `GET:/prefix/` especially easy to
overlook.)

## Exploit chain

```
App:  register(admin, {prefix:'/admin'});  admin.get('/', adminHandler)
      onRoute-built registry protects:  { GET:/admin, HEAD:/admin, HEAD:/admin/ }   // no GET:/admin/
      central onRequest: if (registry.has(METHOD:url)) require auth

Attacker:
  GET /admin    (no token)  -> registry has GET:/admin   -> 401 DENIED
  GET /admin/   (no token)  -> registry MISSING GET:/admin/ -> gate passes -> adminHandler runs -> 200 secret
```

## How to run

```bash
cd security-pocs/L1-onroute-trailing-slash-auth-bypass
node poc.js
```

The PoC builds a realistic app: a central `onRequest` gate that consults a
protected-route set populated from `onRoute`, and an `/admin` plugin with an
index route. It then hits `/admin` and `/admin/` with no credentials.

### Expected output

```
=== L1 PoC: onRoute trailing-slash twin -> auth bypass ===

Routes the app "knows about" via onRoute (its protected set):
   GET:/admin
   HEAD:/admin
   HEAD:/admin/
  ^ note: GET:/admin/ is MISSING — the twin was never announced

GET /admin   (no token) -> 401  {"error":"DENIED","route":"GET:/admin"}
GET /admin/  (no token) -> 200  {"secret":"ADMIN DASHBOARD DATA"}

==> VULNERABLE: the auth gate blocked /admin but /admin/ leaked the protected data
    unauthenticated. The trailing-slash twin bypasses the onRoute-based control.
```

Generalizes to nested prefixes (`GET /api/v1/users/` etc.).

## Impact

- Unauthenticated access to handlers that an `onRoute`-driven control believes
  are protected. Same blind spot silently disables `onRoute`-based rate limits,
  WAF rules, audit and API-doc coverage for the twin path.

## Suggested remediation

- Framework: announce the trailing-slash twin to `onRoute` too (so security
  plugins see `GET:/prefix/`), or provide a documented, enumerable list of *all*
  matchable paths. At minimum, document that `onRoute` does not fire for the
  `prefixTrailingSlash:'both'` twin.
- App (mitigation today): set `ignoreTrailingSlash: true`, or enforce auth with
  a route-level/`addHook` hook (which the twin *does* inherit) rather than an
  external onRoute registry, or normalize trailing slashes at the edge.

## References

- `lib/route.js` — `prepareRoute` (the `'both'` branch) and `addNewRoute` (the
  `prefixing === false` gate on `onRoute`).
- Fastify docs: `prefixTrailingSlash`, `onRoute` hook.
