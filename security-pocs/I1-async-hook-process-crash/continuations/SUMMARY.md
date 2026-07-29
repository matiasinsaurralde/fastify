# Summary — the three async-continuation crash variants

## The variants

One identical trigger — a handler that returns an **object under a non-JSON
content-type**, so Fastify's `reply.send` throws `FST_ERR_REP_INVALID_PAYLOAD_TYPE`
(an error Fastify itself tags `statusCode: 500`), with **no header and no
untrusted data** — reached through three different async continuations:

| variant | async source (app code) | unguarded continuation |
|---|---|---|
| `v1-onsend.js` | async `onSend` hook | `hooks.js:309` |
| `v2-prehandler.js` | async `preHandler` / auth | `hooks.js:253` |
| `v3-validation.js` | async validation (`$async`) | `handle-request.js:133` |

All three crash the process. The **synchronous** counterpart of each (sync
hook / sync validator) is caught by `handler()`'s try/catch and returns a graceful
**500**, server survives. So: **sync = 500, async = whole-process crash.**

## Rationale

To isolate the defect from any "input handling" explanation. The base I1 crash
goes through an invalid response *header*, which invites a "the app put bad data
in a header" reading. These three remove headers and untrusted data entirely —
the only "bad" thing is the handler returning the wrong *type*, a plain
500-class bug Fastify already handles on the sync path. What flips the outcome
between *500* and *crash* is not the app's data but **which Fastify code path
caught the error**. That is a framework robustness defect (CWE-248 / CWE-755): a
recoverable, `statusCode:500`-tagged error is escalated to an
`unhandledRejection` / process abort on the async continuations.

## The Node.js policy (Fastify's SECURITY.md extends it)

> "If an application callback throws an uncaught exception, any resulting crash
> is not considered a vulnerability in Node.js. … where the crash depends on
> **application callbacks throwing** uncaught exceptions, [it] will not be treated
> as … vulnerabilities. It is the application's responsibility to handle
> unexpected callback input and **report errors without throwing uncaught
> exceptions**."

Applied here: **no application callback throws in any of the three.** The hooks,
the validator, and the handler all complete successfully; it is Fastify's *own*
code (`onSendEnd`, `reply.js:674`) that throws. So the "callback throws" carve-out
does not literally describe these cases. Read strictly, the closing sentence
points *at Fastify* — Fastify received unexpected input (a wrong return type) and
threw an uncaught exception instead of **reporting** the error, which it does
correctly (as a 500) on the sync path and fails to do on the async path.

## Do they fit the maintainer's characterization?

> *"It is a valid bug, but passing unsanitized data to everywhere (including
> headers, database, etc) is the security issue for that application instead of
> framework."*

- **"It is a valid bug"** — yes; these confirm it (verified crashes, exact stacks).
- **"passing unsanitized data … is the app's issue"** — this *reasoning does not
  apply* to the three variants: there is **no data**, sanitized or not, anywhere
  in the trigger. The crash is caused by an object **return type**, not by any
  header/DB/query value. They are the direct counterexample to the "unsanitized
  data" framing.
- **But, honestly:** the *trigger* is still **trusted application code** (an async
  hook + a wrong return type), which SECURITY.md declares trusted. So while the
  maintainer's *rationale* is inaccurate for these, a *different* rationale
  ("trusted-app-code-triggered crash") can still place them outside the
  **security-advisory** scope.

## Verdict

A **valid framework robustness bug**, and **not** an "unsanitized data" problem
(no data is involved). But because the trigger is trusted app code, pursue it as
a **hardening fix** — guard the async continuations so they fail closed to the
error handler exactly like the sync path — rather than as a CVE. The strongest
*security* framing remains the **base I1**, where untrusted network input (an
invalid header value) reaches Fastify's core `writeHead`.
