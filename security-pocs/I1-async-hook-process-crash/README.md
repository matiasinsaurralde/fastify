# I1 — Remote unauthenticated process crash via unguarded async hook-runner continuation

| | |
|---|---|
| **Severity** | **HIGH** |
| **Class** | Remote Denial of Service — uncaught exception / process crash |
| **CWE** | CWE-248 (Uncaught Exception), CWE-755 (Improper Handling of Exceptional Conditions) |
| **Component** | `lib/hooks.js` (async hook runner) × `lib/reply.js` (`safeWriteHead`/`onSendEnd`) — Fastify core |
| **Auth required** | No |
| **Affected** | `fastify@5.10.0` |

## Summary

A single unauthenticated HTTP request can crash the entire Fastify **process**
(Node aborts with a non-zero exit code) when the application has an **async
`onSend` or `preSerialization` hook** and a response header ends up holding an
attacker-controlled invalid character.

The most natural trigger is an app that reflects a request value into a response
header from an async `onSend` hook — a very common pattern (CORS origin
reflection, correlation/trace-id echo, custom response headers). The attacker
simply puts a newline (or any character Node rejects in a header value) into
that request value.

This is a **framework defect, not an app bug**: the *identical* invalid header,
when set on the normal synchronous handler path, is caught by Fastify and turned
into a graceful `500` — the process survives. Only the async-hook path crashes,
because that path runs the failing operation inside a discarded promise with no
error handling.

## Attacker model & preconditions

- Remote client, no authentication.
- Precondition (app side): an **async** (returns a Promise / `async` function)
  `onSend` or `preSerialization` hook is registered, and some response header
  value is derived from the request (query, header, param, body). Reflecting
  request data into headers via hooks is idiomatic and widespread.
  - A broader variant (see *Related* below) needs only async validation / an
    async `preValidation`/`preHandler` hook plus a handler whose return value
    makes `reply.send` throw.

## Root-cause analysis

### 1. The async hook runner discards its promise

`lib/hooks.js` — `onSendHookRunner` (used for both `onSend` and, via
`preSerializationHookRunner = onSendHookRunner`, `preSerialization`):

```js
// lib/hooks.js  (onSendHookRunner)
    let result
    try {
      result = functions[i++](request, reply, payload, next)   // (a) hook INVOCATION
    } catch (error) {
      cb(error, request, reply)                                // sync throw -> handled
      return
    }
    if (result && typeof result.then === 'function') {
      result.then(handleResolve, handleReject)                 // (b) DISCARDED promise
    }
  }

  function handleResolve (newPayload) {
    next(null, newPayload)                                     // (c) runs the terminal cb
  }
```

- The `try/catch` at (a) only guards the **invocation** of the hook. A hook that
  *throws synchronously* or *rejects* is handled (`cb(error…)` / `handleReject`).
- When the hook is async and **resolves successfully**, `handleResolve` (c) runs
  `next()`, which — once all hooks are consumed — invokes the terminal callback
  `cb` = `wrapOnSendEnd` → `onSendEnd`. All of this executes **inside the
  `.then()` continuation of the promise created at (b)**, and that promise is
  never stored, awaited, or given a `.catch()`. Any throw here becomes an
  **unhandledRejection**.

### 2. The terminal callback can throw on an attacker-controlled header

`lib/reply.js` — `onSendEnd` calls `safeWriteHead`, which **re-throws**
everything except "headers already sent":

```js
// lib/reply.js
function safeWriteHead (reply, statusCode) {
  const res = reply.raw
  try {
    res.writeHead(statusCode, reply[kReplyHeaders])   // Node validates header values here
  } catch (err) {
    if (err.code === 'ERR_HTTP_HEADERS_SENT') {
      reply.log.warn(/* … */)
    }
    throw err                                         // <-- ERR_INVALID_CHAR is re-thrown
  }
}
```

If any header value contains a character Node forbids (CR, LF, NUL, non-Latin1,
…), `res.writeHead` throws `ERR_INVALID_CHAR`. On the async-hook path that throw
propagates out of `handleResolve` → rejects the discarded promise →
**unhandledRejection → Node aborts the process** (default since Node 15).

### 3. Why it's a framework bug: sync vs. async asymmetry

The exact same bad header set on the **synchronous** path (handler sets the
header, no async `onSend` hook) is caught and converted to a graceful `500` —
the server stays up. Fastify has error recovery *everywhere except* the async
hook-runner continuation. The PoC demonstrates both sides.

## Exploit chain

```
GET /?v=%0Ainjected
  → matched handler runs, returns {ok:true}
  → async onSend hook runs:  reply.header('x-echo', req.query.v)   // value = "\ninjected"
  → hook resolves → hooks.js handleResolve → next → onSendEnd → safeWriteHead
  → res.writeHead(...)  throws ERR_INVALID_CHAR   (invalid header value)
  → throw escapes the discarded .then() continuation → unhandledRejection
  → Node aborts:  process exits 1     (entire server dies)
```

## How to run

```bash
cd security-pocs/I1-async-hook-process-crash
node poc.js
```

The script forks a child that runs the vulnerable server (so the crash is
isolated and the harness can print a verdict), fires one request, and reports
the child's exit code.

### Expected output

```
=== I1 PoC: remote unauthenticated process crash ===

[harness] vulnerable server up on 127.0.0.1:45009
[harness] firing ONE unauthenticated request:  GET /?v=%0Ainjected
          (%0A = newline -> invalid HTTP header character)

node:_http_outgoing:628
    validateHeaderValue(key, value);
    ^
TypeError [ERR_INVALID_CHAR]: Invalid character in header content ["x-echo"]
    at safeWriteHead (/home/user/fastify/lib/reply.js:576:9)
    at onSendEnd (/home/user/fastify/lib/reply.js:688:3)
    at wrapOnSendEnd (/home/user/fastify/lib/reply.js:569:5)
    at next (/home/user/fastify/lib/hooks.js:292:7)
    at handleResolve (/home/user/fastify/lib/hooks.js:309:5)
    at process.processTicksAndRejections (node:internal/process/task_queues:103:5)

[harness] client socket error: ECONNRESET (expected: server died mid-response)
[harness] SERVER PROCESS EXITED  code=1  signal=null

==> VULNERABLE: a single unauthenticated request crashed the whole server process.
```

The stack trace is the smoking gun: `handleResolve (hooks.js:309)` →
`next (hooks.js:292)` → `onSendEnd`/`safeWriteHead` → uncaught in
`processTicksAndRejections`.

## Impact

- One unauthenticated request kills the whole process; all in-flight requests on
  that worker are dropped. Repeat to keep it down (crash-loop DoS) even behind a
  process supervisor / cluster — an attacker can hold every worker down at will.
- No special privileges, no valid route data, no body needed — just a query
  string (or any request-controlled header value).

## Variant — the invalid character need not be an attack (`poc-variant-benign-unicode.js`)

The base PoC uses a newline (`%0A`), which reads like a header-injection attempt.
But the crash is triggered by **any** Unicode code point > 0xFF, i.e. ordinary
international text — an emoji, a CJK name, `€`, Cyrillic. (Node's
`validateHeaderValue` rejects code points > 0xFF the same way it rejects control
characters; raw request-header bytes stay Latin1, but **query/body/param values
are UTF-8 decoded into real Unicode strings**, so they carry > 0xFF code points.)

The variant app just echoes a query label into a response header — a completely
ordinary pattern (trace id, cache key, debug, personalization). Verified output:

```
GET /?label=hello                  -> 200   (plain ASCII, fine)
GET /?label=%E6%9D%B1%E4%BA%AC     (label = "東京" — ordinary text, NOT an attack)
  TypeError [ERR_INVALID_CHAR] ... at safeWriteHead (reply.js:576) ... handleResolve (hooks.js:309)
SERVER PROCESS EXITED  code=1
```

**Why it matters:** the crash is not gated on a malicious/CRLF payload, so
"sanitize untrusted input" neither describes nor prevents it — the value is valid
text a legitimate international user might send. To stop it app-side you would
have to strip every non-Latin1 character from every reflected value, which is not
what "sanitization" means and which no one does. This is the clearest evidence
that the defect is the framework escalating a routine `ERR_INVALID_CHAR` (a 500
on the sync path) into a whole-process crash on the async hook path — not an
application input-handling mistake.

Run: `node poc-variant-benign-unicode.js`

## Related (not in this PoC, documented in `../../findings.md`)

- **I-C2** — same root cause reached via **async validation** (a stock AJV
  `$async` schema or custom async validator) or an async `preValidation`/
  `preHandler` hook, combined with a handler whose return makes `reply.send`
  throw (e.g. a non-JSON content-type returning an object). The throw at
  `lib/handle-request.js:221` escapes the async boundary the same way.
- The same unguarded-continuation shape also exists in other hook runners
  (`hooks.js:253`, `handle-request.js:133`).

## Suggested remediation

Wrap the async hook-runner continuation so a throw in `next`/terminal-`cb` is
routed to the error handler instead of the socket, e.g.:

```js
function handleResolve (newPayload) {
  try {
    next(null, newPayload)
  } catch (err) {
    cb(err, request, reply)          // hand to the normal error path -> 500
  }
}
```

(and equivalently guard the other unguarded continuations). This restores the
sync/async symmetry so a bad header becomes a `500`, never a process crash.

## References

- `lib/hooks.js` — `onSendHookRunner` / `handleResolve`
- `lib/reply.js` — `safeWriteHead`, `onSendEnd`
- Node.js: unhandled promise rejections terminate the process by default since
  Node 15 (`--unhandled-rejections=throw`).
