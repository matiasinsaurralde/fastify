# B1 — O(n²) URL-decode DoS via repeated `%25` in the request path

| | |
|---|---|
| **Severity** | **MEDIUM** under default config · **HIGH** with a raised URL/header size limit |
| **Class** | Algorithmic-complexity Denial of Service |
| **CWE** | CWE-407 (Inefficient Algorithmic Complexity) |
| **Component** | `node_modules/find-my-way/lib/url-sanitizer.js` (`safeDecodeURI`) — Fastify's router dependency |
| **Auth required** | No |
| **Affected** | `find-my-way@9.7.0` as used by `fastify@5.10.0` |

## Summary

Fastify routes every request through `find-my-way`, whose `safeDecodeURI`
rebuilds the **entire path string** each time it encounters a `%25` escape,
inside a per-character loop. A path composed of many `%25` sequences therefore
costs **O(n²)**. The decode runs **on every request, pre-authentication, before
any hook/handler and before `maxParamLength` is checked**, so it cannot be
avoided by route-level protections.

Under Node's default 16 KB URL cap this is a strong per-request CPU amplification
(each malicious request blocks the single event-loop thread for ~tens of ms —
hundreds of times a benign request). If the operator has raised
`--max-http-header-size` (common for apps with large JWT/session cookies), a
single request freezes the event loop for **seconds to minutes**.

## Attacker model & preconditions

- Remote client, no authentication, no valid route required (404s trigger it
  too).
- Default config: bounded to per-request amplification by the 16 KB URL cap.
- Elevated impact: any deployment that raised the URL/header size limit.

## Root-cause analysis

`node_modules/find-my-way/lib/url-sanitizer.js` — inside `safeDecodeURI`'s loop,
the `%25` special case (which exists to prevent double-decoding of an encoded
percent sign) rebuilds the whole string:

```js
// url-sanitizer.js — safeDecodeURI (per-character loop)
for (let i = 1; i < path.length; i++) {
  const charCode = path.charCodeAt(i)
  if (charCode === 37) {                       // '%'
    // …
    } else {
      shouldDecodeParam = true
      if (highCharCode === 50 && lowCharCode === 53) {           // "%25"
        shouldDecode = true
        path = path.slice(0, i + 1) + '25' + path.slice(i + 1)   // <-- O(n) full rebuild, PER %25
        i += 2
      }
      i += 2
    }
  }
  // …
}
```

Each `%25` copy triggers an O(n) `slice/concat` rebuild of `path`. With
`k = n/3` copies of `%25`, total work is O(k·n) = **O(n²)**.

Reachability — Fastify hands the raw URL straight to the router with no
pre-decode, and `safeDecodeURI` is the first thing `find-my-way.find()` does:

```js
// find-my-way/index.js — find()
try {
  sanitizedUrl = safeDecodeURI(path, this.useSemicolonDelimiter)  // runs on EVERY request
  // …
} catch (error) {
  return this._onBadUrl(path)
}
// maxParamLength is only checked AFTER this, deeper in matching
```

Only the `%25` branch mutates the string; other escapes (`%2F`, `%20`, `%41`, …)
stay linear — confirmed in the PoC's density check.

## Exploit chain

```
GET /%25%25%25 … %25   (path = thousands of "%25")
  → find-my-way.find() → safeDecodeURI() → O(n^2) string rebuilds
  → event-loop thread blocked BEFORE auth/hooks
```

## How to run

```bash
cd security-pocs/B1-percent25-url-decode-dos
node poc.js
```

The PoC has two parts: **(A)** a unit-level scaling table of `safeDecodeURI`
(showing the O(n²) growth and the seconds-scale cost reachable with a raised
limit), and **(B)** an end-to-end test against a real Fastify server under
default config (amplification + the 16 KB→431 cap).

### Expected output (numbers vary by hardware)

```
=== B1 PoC: %25 O(n^2) URL-decode DoS ===

PART A — safeDecodeURI() cost vs. path length (repeated %25):
     3000 chars  ->       1.31 ms   (baseline)
     6000 chars  ->       1.59 ms   (1.22x vs prev)
    15000 chars  ->      14.00 ms   (8.82x vs prev)
    30000 chars  ->      85.34 ms   (6.10x vs prev)
    60000 chars  ->     333.38 ms   (3.91x vs prev)
   120000 chars  ->    4516.92 ms   (13.55x vs prev)
   (benign path of 60000 plain chars -> 0.78 ms)
   Doubling the length ~4x the time => O(n^2).

PART B — end-to-end on a real server (default 16 KB URL cap):
   benign 15 KB URL   -> HTTP 200  in 12.4 ms
   %25    15 KB URL   -> HTTP 200  in 29.0 ms  (amplified)
   %25   ~18 KB URL   -> HTTP 431  in 2.4 ms  (Node URL cap -> 431)

==> CONFIRMED: pre-auth, per-request quadratic CPU.
```

Note the ~430× gap between a benign 60 KB path (0.78 ms) and a `%25` path of the
same length (333 ms), and the clean quadratic doubling in Part A.

## Impact

- **Default config:** unauthenticated amplification flood — each ≤16 KB request
  burns ~tens of ms of synchronous CPU and blocks *all* concurrent clients
  (Node is single-threaded). A modest request rate saturates a core; the latency
  floor for every legitimate request rises.
- **Raised `--max-http-header-size`:** a single request freezes the event loop
  for seconds to minutes (measured 256 KB→~32 s, 512 KB→~118 s by an independent
  reviewer) — a one-shot outage.

## Suggested remediation

- Fix the algorithm: don't rebuild the whole string per `%25`. Track an offset /
  build the output once (single pass), making the decode O(n).
- Defense in depth: cap raw path length before decoding; keep the URL size limit
  conservative.

## References

- `node_modules/find-my-way/lib/url-sanitizer.js` — `safeDecodeURI` (the `%25`
  rebuild).
- `node_modules/find-my-way/index.js` — `find()` (calls `safeDecodeURI` first;
  `maxParamLength` is checked only afterward).
