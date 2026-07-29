# I1 — same defect, three async continuations (no header anywhere)

Three PoCs with the **identical trigger** — a handler that returns an object
under a non‑JSON content‑type, so `reply.send` throws
`FST_ERR_REP_INVALID_PAYLOAD_TYPE` (an error Fastify itself tags
`statusCode: 500`), with **no header and no untrusted data** — reached through
three different unguarded async continuations. All three crash the process
(verified, Node 22).

| PoC | async source (app code) | unguarded continuation | crash stack (top → root) |
|-----|-------------------------|------------------------|--------------------------|
| `v1-onsend.js` | async `onSend` hook | `hooks.js:309` (`onSendHookRunner` `handleResolve`) | `onSendEnd:674 → wrapOnSendEnd:569 → next:292 → handleResolve:309` |
| `v2-prehandler.js` | async `preHandler`/auth | `hooks.js:253` (hook‑runner `handleResolve`) | `onSendEnd:674 → Reply.send:232 → preHandlerCallbackInner:221 → preHandlerCallback:168 → next:236 → handleResolve:253` |
| `v3-validation.js` | async validator (`$async` behaves the same) | `handle-request.js:133` (`validationErr.then(cb,cb)`) | `onSendEnd:674 → Reply.send:232 → preHandlerCallbackInner:221 → preHandlerCallback:168 → validationCompleted:158 → processTicksAndRejections` |

Note on v3: line 133 is where the discarded `.then(cb, cb)` continuation is
registered; the crash surfaces through its callback `validationCompleted`
(`:158`), then the microtask runner — so the stack shows `:158`, not a literal
`:133` frame, but `:133` is the unguarded site whose rejection is never caught.

Run: `node v1-onsend.js`, `node v2-prehandler.js`, `node v3-validation.js`.

## Root cause (shared)

One class, three sites: an async continuation in the request lifecycle invokes
downstream code that reaches a throwing send/serialize/writeHead operation, but
runs it inside a **discarded promise with no `try/catch`**. The identical error
on the fully‑synchronous path is caught and returned as a `500`; on these async
paths it becomes an `unhandledRejection` → process abort. Same root cause, same
fix shape (route the continuation throw to the error handler); three distinct
lines that each need the guard.

## Sync counterparts are guarded (the asymmetry)

The same trigger with a **synchronous** hook/validator is caught and returned as
a graceful `500`; the server survives. Verified for all three:

```
SYNC /v1 (sync onSend)     -> 500
SYNC /v2 (sync preHandler) -> 500
SYNC /v3 (sync validator)  -> 500
>>> server SURVIVED all three sync versions (no crash) <<<
```

So sync = guarded, async = crash. The guard is `handler()`'s try/catch in
`handle-request.js`; it wraps the fully-synchronous chain but not the deferred
async continuations.

## Note on threat model (Fastify SECURITY.md extends Node.js)

Two honest caveats for anyone reporting these:

1. **No application callback throws in any variant.** The hooks/validator/handler
   all *complete successfully*; it is Fastify's OWN code (`onSendEnd`,
   `reply.js:674`) that throws `FST_ERR_REP_INVALID_PAYLOAD_TYPE` — an error
   Fastify tags `statusCode:500` and catches on the sync path. So Node's CWE-248
   carve-out ("crash depends on *application callbacks throwing* uncaught
   exceptions") does not literally describe these; read strictly it points the
   other way (the framework should "report errors without throwing uncaught
   exceptions", which it does on the sync path).
2. **But the trigger is application code** (an async hook/validator + a handler
   returning the wrong type), which SECURITY.md declares *trusted*, and none of
   the payload-type variants require untrusted input. So as **security
   advisories** they are weak and likely to be classified under "Application
   code" — expect a maintainer to apply the CWE-248/"trusted code" spirit. Their
   real value is as evidence of a **framework robustness defect** worth fixing,
   not as CVEs. The strongest *security* framing is the base I1, where
   **untrusted network input** (an invalid header value) reaches Fastify's core
   `writeHead` — see `../poc.js` / `../poc-variant-benign-unicode.js`.
