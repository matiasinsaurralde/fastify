# Fastify 5.10.0 — Security PoCs

Proof-of-concept exploits for five remotely-exploitable vulnerabilities found in
`fastify@5.10.0` (this repository) and its dependency tree, via first-principles
code analysis. Each finding lives in its own subdirectory with a self-contained,
runnable PoC and a full write-up.

> ⚠️ **Authorized-testing only.** These PoCs start a local Fastify server on
> `127.0.0.1` and attack *that* server. Do not point them at systems you do not
> own or are not authorized to test. Two of them intentionally crash / freeze a
> process; run them in a throwaway shell.

## The findings

| # | Dir | Severity | Class | One-line |
|---|-----|----------|-------|----------|
| **I1** | [`I1-async-hook-process-crash`](./I1-async-hook-process-crash/) | **HIGH** | Remote process crash (CWE-248/CWE-755) | One unauthenticated request crashes the whole process when an async `onSend` hook reflects request data into a header |
| **C1** | [`C1-uniqueitems-eventloop-dos`](./C1-uniqueitems-eventloop-dos/) | **HIGH** (conditional) | Algorithmic-complexity DoS (CWE-407) | One small `uniqueItems` array body freezes the event loop for tens of seconds |
| **L1** | [`L1-onroute-trailing-slash-auth-bypass`](./L1-onroute-trailing-slash-auth-bypass/) | **MED-HIGH** | Authorization bypass (CWE-289/CWE-863) | The trailing-slash twin of a prefixed plugin's `/` route is reachable but invisible to `onRoute`-based auth |
| **B1** | [`B1-percent25-url-decode-dos`](./B1-percent25-url-decode-dos/) | **MED** (HIGH w/ raised header cap) | Algorithmic-complexity DoS (CWE-407) | `%25`-repeated URL path drives an O(n²) decode, pre-auth, on every request |
| **G1** | [`G1-trailer-content-length-desync`](./G1-trailer-content-length-desync/) | **MED** | Response-framing desync / smuggling (CWE-444) | HEAD to a `reply.trailer()` route emits both `Content-Length` and `Transfer-Encoding: chunked` |

The single strongest / most novel is **I1** — a genuine Fastify core defect (not
an app footgun): the same invalid header that Fastify gracefully turns into a 500
on the sync path crashes the process on the async-hook path.

## Requirements

- Node.js ≥ 18 (validated on v22). Node ≥ 15 is required for I1 (default
  crash-on-unhandled-rejection).
- Dependencies installed at the repo root (`npm install` in `/…/fastify`). The
  PoCs load Fastify via `require('../../fastify.js')`, so its dependency
  resolution uses the repo's `node_modules` automatically — no `NODE_PATH` needed.

## Running

Each PoC is a single self-contained script that prints a clear `==> VULNERABLE`
verdict and exits `0` on success:

```bash
cd security-pocs/I1-async-hook-process-crash && node poc.js
cd security-pocs/C1-uniqueitems-eventloop-dos && node poc.js   # ~30–60s (freeze)
cd security-pocs/L1-onroute-trailing-slash-auth-bypass && node poc.js
cd security-pocs/B1-percent25-url-decode-dos && node poc.js
cd security-pocs/G1-trailer-content-length-desync && node poc.js
```

Or run them all:

```bash
for d in security-pocs/*/; do echo "== $d =="; (cd "$d" && node poc.js); echo; done
```

## Verification status

Every finding here was reproduced end-to-end on a real Fastify server by the
author. Preconditions and honest severity ceilings (e.g. B1 is bounded to
MEDIUM under Node's default 16 KB URL cap; C1 requires a `uniqueItems` schema
without `maxItems`) are stated in each subdirectory's README. Additional
candidates that were NOT independently reproduced (async-validation crash
variant, `regexCache` OOM, `removeAdditional` stripping, a dev-tainted
`new Function` sink, etc.) are documented in the repo-root `findings.md`, not
here.

## Suggested fixes (summary)

- **I1** — wrap the async hook-runner continuation (`lib/hooks.js` `handleResolve`
  → `next` → terminal `cb`) in a `try/catch` that routes to the error handler.
- **C1** — cap array length before `uniqueItems` runs (document/encourage
  `maxItems`), or reject over-large arrays pre-validation.
- **L1** — fire `onRoute` for the trailing-slash twin (or expose it so security
  plugins can see both paths).
- **B1** — build the decoded string once instead of rebuilding it per `%25`
  (track an offset), and/or cap path length before decoding.
- **G1** — delete a stale `Content-Length` when switching to trailer/chunked
  framing in `onSendEnd`.
