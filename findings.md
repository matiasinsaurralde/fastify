# Fastify 5.10.0 — Zero-Day Vulnerability Discovery

Target: `fastify@5.10.0` (this repo). Attacker model: remote HTTP client (auth or unauth) controlling method, path, query, headers, content-type/length, transfer-encoding, and body.

Goal classes: process crash (DoS), RCE, auth/limit/validation bypass, cross-request data leakage, prototype pollution.

Method: first-principles code analysis (NO git history / changelog / internet diffing). Dependencies audited too.

---

## EXECUTIVE SUMMARY — confirmed, remotely-exploitable findings (all independently PoC-verified)

Severities below are POST adversarial-verification (agent V independently re-PoC'd B1/C1/A1 and bounded them; honest ceilings shown).

| ID | Sev | Class | One-line | Precondition | Verified by |
|----|-----|-------|----------|--------------|-------------|
| **I1** | **HIGH** | Remote process crash | Unguarded async hook-runner continuation (`hooks.js:303-310`): a sync throw in the terminal `cb` (`onSendEnd`→`safeWriteHead` on an invalid header) → unhandledRejection → **Node aborts**. `GET /?v=%0A` kills the server | app has an **async `onSend`/preSerialization hook** reflecting request data into a header (or async validation/auth + throw-on-send handler) | me (live, exit 1) + agent I |
| **C1** | **HIGH** (conditional) | DoS (algorithmic) | O(n²) event-loop freeze from a `uniqueItems:true` array body (AJV `loopN2`); 1 MB → ~25 s–3 min, whole server starved | route declares `uniqueItems` on an array of objects / no scalar `items` and no `maxItems` (AJV footgun) | me + agents C, J, V (quad) |
| **L1** | **MED-HIGH** | Auth bypass | `onRoute` never fires for the auto-registered trailing-slash twin of a prefixed plugin's `/` route (`route.js:262` `prefixing:true` + `:293` gate) → `GET /prefix/` reachable but invisible to onRoute-based authz/WAF/rate-limit | route at `/` in a prefixed plugin + onRoute-enumeration security control | me + agent L |
| **B1** | **MED** default / **HIGH** raised-header | DoS (algorithmic) | O(n²) in `find-my-way/url-sanitizer.js:66` (`%25` path rebuild), pre-auth, every request. Node caps URL at 16 KB → ~20–28 ms/req amplification by default; with raised `--max-http-header-size` (common) 256 KB→32 s, 512 KB→118 s single-request freeze | none by default (amplification); one-shot needs raised header cap | me + agents B, V |
| **G1** | **MED** | Response-framing desync | HEAD (or CL-set) to a `reply.trailer()` GET route emits both `Content-Length` and `Transfer-Encoding: chunked` (`reply.js:590-601` skips CL cleanup) → smuggling/cache-poisoning primitive | route uses `reply.trailer()`; non-RFC-strict intermediary | me + agent G |
| A1 | LOW (documented) | Validation skip | content-form body schema skips validation on a media-type miss (`validation.js:174`) | **documented behavior** (docs ⚠ warning, `Validation-and-Serialization.md:253,260-274`); content-form + non-default object parser; default = string only | me + agents A, V |

Secondary candidates: **I-C2** (async validation/auth + throw-on-send handler → same crash; broader trigger), **B2** (unbounded regexCache OOM if RegExp host constraint used), **C2** (`removeAdditional:true` strips props defined under `allOf`/`oneOf`/`$ref`/`if-then` → data-loss/situational bypass), **K1** (find-my-way `_compileCreateParamsObject` builds `new Function` from an unescaped route param name → RCE if param names ever derive from untrusted input — a chaining primitive), **L2** (synthetic HEAD announced to onRoute as method:HEAD → per-verb guard bypass + existence oracle), **G2/G3** (trailer CL+TE variants).

Ruled out (with PoCs): prototype pollution (D — secure-json-parse + flat query parser hardened), cross-request shared-state/race leakage (E — 6000+ concurrent/pipelined reqs, 0 leaks), trust-proxy/IP-spoof & response-splitting (F — correct; Node blocks CRLF), remote RCE (K — all codegen sinks take dev-authored source; request data is runtime-arg-only), request-side HTTP smuggling (G — llhttp frames, Fastify drains/closes).

Strongest, most novel finding: **I1 — a single unauthenticated request crashes the whole Fastify process** (core hook-runner defect, not an app footgun). Themes: (a) unguarded async continuations turn a would-be 500 into a process kill; (b) unbounded attacker input drives O(n²) routines on the single event-loop thread; (c) core route/hook bookkeeping (onRoute twin, CL+TE) diverges from what security controls observe.

---

## Approach Family Registry

| # | Family | Scope | Status |
|---|--------|-------|--------|
| A | Content-Type / charset / body parsing | content-type-parser.js, content-type.js, handle-request.js, rawBody | **CANDIDATE (A1)** — reported |
| B | Routing / find-my-way / constraints | find-my-way, route.js, four-oh-four.js | **✅ CONFIRMED B1 (HIGH DoS)** + B2 (MED) — done; route-confusion/constraint-bypass ruled out |
| K | RCE / code-generation sink audit | fast-json-stringify, ajv-compiler, find-my-way new Function() | **done** — no remote RCE; K1 dev-tainted codegen sink (chaining primitive) |
| L | Encapsulation / hook-scope / auth-bypass | route.js, head-route.js, hooks.js, four-oh-four.js, plugin-override.js | **✅ CONFIRMED L1 (MED-HIGH auth bypass)** + L2 — done; HEAD-skips-preHandler disproved |
| M | Logging path (pino) crash/DoS/log-injection | logger-factory.js, log-controller.js, pino, pino-std-serializers | OPEN — running (wave 3) |
| V | Adversarial verification of B1/C1/A1 | independent PoCs, severity bounding | **done** — B1→MED(default)/HIGH(raised); C1→HIGH(conditional); A1→LOW(documented) |
| C | Validation / serialization / mass-assignment | validation.js, schema-controller.js, ajv-compiler, fast-json-stringify | **✅ CONFIRMED C1 (HIGH DoS)** + C2 (MED) — done; response-leak ruled out |
| D | Prototype pollution chains | secure-json-parse, query parsing, params, decorate.js, defaults | **BLOCKED** — hardened, no mechanism |
| E | Cross-request state leakage / lifecycle / race | request.js, reply.js, context.js, hooks.js, handle-request.js, toad-cache | OPEN — running |
| F | Trust-proxy / header parsing / reply header injection | proxy-addr, request.js (ip/host/proto), reply.js headers | OPEN — running |
| G | HTTP framing / request smuggling / keep-alive desync | Fastify↔Node HTTP boundary, TE/CL, QUERY, pipelining | **✅ CONFIRMED G1 (MED desync)** + G2/G3 — done; request-side smuggling safe |
| I | Error/hook state machine / crash / double-send | error-handler.js, hooks.js, wrap-thenable.js, content-type-parser done() | **✅ CONFIRMED I1 (HIGH remote crash)** + I-C2 — done |
| J | DoS / resource exhaustion / ReDoS / stack overflow | JSON.parse, AJV, fast-json-stringify, fmw | **done** — corroborates C1 (HIGH); no crash (all caught→500) |

---

## Confirmed / Candidate Findings

### ✅ CONFIRMED I1 — [HIGH] Remote unauthenticated PROCESS CRASH via unguarded async hook-runner continuation
- **Root cause (Fastify core)**: `onSendHookRunner`/`preSerializationHookRunner` (`lib/hooks.js:303-310`) run an async hook's promise as `result.then(handleResolve, handleReject)` — a **discarded promise**. `handleResolve` → `next` → terminal `cb` (`wrapOnSendEnd` → `onSendEnd` → `safeWriteHead`) runs SYNCHRONOUSLY inside that continuation. A sync throw there (e.g. `res.writeHead` on an invalid header value — `safeWriteHead` re-throws non-HEADERS_SENT errors at `reply.js:576-582`) is NOT caught (the try/catch at `hooks.js:297` only guards the hook INVOCATION, not the continuation) → **unhandledRejection → Node ≥15 aborts the process**. (Sibling unguarded continuations: `hooks.js:253`, `handle-request.js:133` async-validation `.then(cb,cb)`.)
- **Trigger (I-C1, cleanest)**: app has an **async `onSend` hook** that reflects a request-derived value into a response header (common: CORS origin reflection, correlation/trace-id echo, custom header plugins), e.g. `async (req,reply,payload)=>{ reply.header('x-echo', req.query.v); return payload }`. Attacker: `GET /?v=%0Ainjected` (newline; also `%00`, emoji/non-Latin1).
- **Independently VERIFIED (my poc-ic1.js, default Node v22.22.2, real server)**: process **exits code 1** with uncaught `TypeError [ERR_INVALID_CHAR]`, stack: `safeWriteHead (reply.js:576) → onSendEnd (reply.js:688) → wrapOnSendEnd (reply.js:569) → next (hooks.js:292) → handleResolve (hooks.js:309) → processTicksAndRejections`. Single request kills the entire server.
- **Trigger (I-C2, HIGH)**: async validation (stock `$async` AJV schema, or custom async validator) OR async preValidation/preHandler (e.g. async auth) + a sync handler whose return makes `reply.send` throw (non-JSON content-type + object return, e.g. a CSV route returning an array). Throw at `handle-request.js:221` escapes the async boundary → unhandledRejection → crash (agent I `poc5`: async-auth + CSV dies on one GET).
- **Impact**: single unauthenticated request → whole-process crash (all in-flight requests dropped; crash-loop DoS even behind a supervisor). Precondition is an app that uses async onSend/preSerialization hooks reflecting request data into headers, or async validation/auth + a throw-on-send handler — realistic patterns. **HIGH.** (I-C3 LOW: out-of-range `error.statusCode`/throwing `error.headers` → response corruption, app-controlled fields, not remotely reachable alone.)
- **Fix**: wrap the hook-runner continuation (`handleResolve`/`next`/terminal cb) in try/catch that routes to the error path, not the socket.

### ✅ CONFIRMED B1 — [MEDIUM default / HIGH with raised header-size] O(n²) event-loop DoS via `%25` in URL path (find-my-way)
- **Post-verification (agent V)**: Node hard-caps the URL at 16 KB (>16 KB → 431), so a single default-config request is bounded to ~20–28 ms event-loop block (amplification flood, ~450× vs benign, saturates a core at modest RPS), NOT a multi-second freeze. The seconds–minutes freeze requires a raised `--max-http-header-size` (V measured 256 KB→32 s, 512 KB→118 s) — a common ops setting for large JWT/cookie apps. Honest severity: **MEDIUM default, HIGH with raised header cap.**
- **Sink**: `node_modules/find-my-way/lib/url-sanitizer.js:66` in `safeDecodeURI()`:
  ```js
  if (highCharCode === 50 && lowCharCode === 53) {   // '%25'
    shouldDecode = true
    path = path.slice(0, i + 1) + '25' + path.slice(i + 1)   // full O(n) rebuild, per %25
    i += 2
  }
  ```
  Inside the per-character loop, EACH `%25` occurrence rebuilds the entire path string → **O(n²)** for a path of `%25` repeats.
- **Reachability**: raw `req.url` → `router.find()` (`fastify.js` routing → find-my-way `index.js:551`) → `safeDecodeURI` runs UNCONDITIONALLY on every request, **pre-auth, before hooks/handlers, before `maxParamLength`** (which is checked after decode → 414 only after CPU is already burned). Applies to any path incl. non-existent routes (404s).
- **Attacker input**: `GET /%25%25%25…%25 HTTP/1.1` (path = many `%25`).
- **Independently VERIFIED (my poc-quad.js)**: path 15 KB (~5000×`%25`) = **6.3 ms/call** vs 0.19 ms benign (33×); doubling length ≈ 4× time (quadratic): 30 KB→29 ms, 60 KB→108 ms. Agent B end-to-end: 90 KB→1.2 s, 150 KB→5.9 s single-request event-loop freeze.
- **Impact**: unauthenticated availability DoS. Default 16 KB URL cap ⇒ ~6 ms synchronous event-loop block per request (single-threaded Node → blocks ALL clients; ~150 req/s saturates a core; strong amplification). With raised `--max-http-header-size` (common for large JWT/cookie apps) ⇒ single request freezes the loop for 1–6 s. Confidence: HIGH (mechanism + measurement).
- **Fix direction**: don't rebuild the string per-occurrence (build once, or track an offset), and/or cap path length before decode.

### ✅ CONFIRMED L1 — [MED-HIGH] `onRoute` blind spot for trailing-slash twin → auth/security-control bypass
- **Root cause (Fastify core)**: for a route declared at path `/` inside a plugin with a non-empty prefix, default `prefixTrailingSlash:'both'` registers TWO routable paths: `''`→`/prefix` (`route.js:259`, `prefixing=false`) and `/`→`/prefix/` (`route.js:262`, **`prefixing:true`**). But onRoute hooks fire only when `prefixing === false` (`route.js:293-298`). So **`GET /prefix/` is fully routable yet NEVER announced to `onRoute`** (only its synthetic HEAD twin is announced).
- **Independently VERIFIED (my poc-l1.js, default `Fastify()`)**: with a common RBAC pattern (central `onRequest` gate consulting a protected-route registry built from `onRoute`): announced keys = `GET:/admin`, `HEAD:/admin`, `HEAD:/admin/` (note **`GET:/admin/` missing**). Result: `GET /admin` (no token) → **401 DENIED**; `GET /admin/` (no token) → **200 `{"secret":"ADMIN DASHBOARD"}`** ⇒ unauthenticated bypass. Generalizes to nested prefixes (`GET /api/v1/users/`).
- **Impact**: any security/observability control that enumerates routes via `onRoute` — RBAC/authorization registries, rate-limiters, WAF policy, CSRF-exemption lists, audit — is BLIND to the trailing-slash twin, which still runs the real handler. Attacker just appends `/`. **MED-HIGH**: real auth-bypass class, gated on the (common) onRoute-enumeration authz/instrumentation pattern; direct route-level hooks, in-scope `addHook`, and `ignoreTrailingSlash:true` all correctly protect the twin (verified by agent L).
- **L2 (MED)**: the auto HEAD route re-enters `onRoute` as `method:'HEAD'` (`route.js:449-452`); per-verb onRoute guards ("guard GET/POST, HEAD harmless") leave it unguarded while HEAD runs the SAME GET handler → side effects + Content-Length/ETag/200-vs-401 existence oracle (body stripped).
- Disproved (agent L, matches my route.js:245 read): `HEAD /secret` does NOT skip a route-level `preHandler` — HEAD clones full options incl. hooks. Path/case/slash normalization and 404 paths: no bypass.

### ✅ CONFIRMED G1 — [MEDIUM] Response-framing desync: `Content-Length` + `Transfer-Encoding: chunked` on same response (reply.trailer + HEAD)
- **Root cause (Fastify core)**: `onSendEnd` (`lib/reply.js:590-601`) sets `Transfer-Encoding: chunked` + `Trailer` when `reply.trailer()` is used but **never deletes a `content-length`** already set; the CL-reconciliation at `reply.js:677-686` is gated on `reply[kReplyTrailers] === null`, so it is skipped when trailers exist. Auto-HEAD's onSend handler (`lib/head-route.js:29-31`) sets `content-length` = body byte size. Net: a HEAD to any GET route that uses `reply.trailer()` emits BOTH headers.
- **Independently VERIFIED (my poc-g1b.js, real server + raw socket)**: `HEAD /data` →
  ```
  HTTP/1.1 200 OK
  content-length: 7
  transfer-encoding: chunked
  trailer: x-checksum
  ```
  (empty body, keep-alive). GET /data correctly uses chunked only. RFC 9112 §6.1 violation confirmed.
- **Impact**: response-framing ambiguity → desync/smuggling primitive. A downstream intermediary that frames the HEAD response by `content-length: 7` reads 7 bytes (`HTTP/1.`) of the FOLLOWING response as the HEAD body, offsetting all subsequent response boundaries → response smuggling / cache poisoning / cross-client response leak. Unauthenticated (attacker just uses HEAD; auto-HEAD default-on). **MEDIUM**: real-world exploit needs a non-RFC-compliant / CL-preferring intermediary (a compliant proxy ignores CL/TE for HEAD). Precondition: a GET route uses `reply.trailer()`.
- **G2 (same root cause, MED)**: caller-set `content-length` + `reply.trailer()` on a non-HEAD GET → CL+TE with a real chunked body (bogus CL over-reads next response). **G3 (LOW)**: `reply.trailer()` + 204/304 → `ERR_HTTP_TRAILER_INVALID` caught → 500 (broken endpoint, not a crash).
- **Fix**: delete `content-length` when switching to trailer/chunked framing in `onSendEnd`.
- **Request-side smuggling = SAFE** (agent G, all live-fired): Node/llhttp is the sole body-framing authority; Fastify early-response paths leave `req._consuming===false` (Node `_dump()` auto-drains CL and chunked) or set `connection: close` on parse errors; llhttp rejects CL+TE / dup-CL below Fastify. Bodyless-with-body, QUERY/415 paths, CL.TE/TE.CL, timeouts, maxRequestsPerSocket — all safe.

### CANDIDATE K1 — [RCE, chaining primitive — NOT remotely reachable in base model] `new Function` route-param-name injection (find-my-way)
- `node_modules/find-my-way/lib/handler-storage.js:71,78`: `_compileCreateParamsObject` concatenates the route **param name** raw into `new Function` source: `params['${params[i]}'] = paramsArray[${i}]` — no escaping. A param name with `'` breaks out → arbitrary JS at compile time. Agent K PoC: `execSync('id')`→uid=0.
- **Taint source is the DEVELOPER route pattern** (`router.on(method, path)`, boot-time). Remote client controls only URL → param VALUES (passed as runtime array arg, never into source). **Not remotely exploitable by itself.** It is a chaining primitive: RCE iff an app/plugin registers routes whose param names derive from untrusted input (user-supplied OpenAPI, DB-driven/multi-tenant dynamic routes). Also #2/#3: constraint/strategy names embedded raw (weaker, dev-tainted). All other codegen sinks (fast-json-stringify, ajv, node.js prefix match) are attacker-safe (dev schema source; request data is runtime arg, escaped).
- Note: `lib/req-id-gen-factory.js` default id is a plain incrementing counter (`req-<base36>`), not crypto — fine as a trace id; only a problem if an app misuses `request.id` as a token (app issue). `requestIdHeader` (default false) would take the id from an attacker header (log-injection/spoof) if enabled. The brief's "encryption sanity checking" hint dead-ends in core (no crypto on the request path).

### CANDIDATE B2 — [MED, conditional] Unbounded `regexCache` memory DoS (find-my-way accept-host)
- `node_modules/find-my-way/lib/strategies/accept-host.js:7,16,22`: if the app registers any **RegExp** `host` constraint, every distinct attacker `Host` header (matches AND non-matches, line 22) is cached permanently in a `Map` with no cap/eviction → unbounded growth → OOM. PoC (agent B): 500k unique hosts → +47 MB. Precondition: app uses a RegExp host constraint (uncommon). Not a data leak (host-keyed, deterministic).

### ✅ CONFIRMED C1 — [HIGH] Single-request event-loop freeze via `uniqueItems:true` O(n²) (AJV)
- **Sink**: AJV `uniqueItems` keyword (`node_modules/ajv/dist/vocabularies/validation/uniqueItems.js`) uses O(n²) `loopN2` (deep `equal()` on every pair) whenever array items are objects/arrays OR have **no `items` type** (`canOptimize()` false). Only scalar `items` type gets the O(n) hash path. Runs synchronously inline on the event loop via `lib/validation.js:123`.
- **Precondition**: a route schema declares `{ type:'array', uniqueItems:true }` without a small `maxItems` (a common "unique list" pattern). Attacker sends a large array body.
- **Independently VERIFIED (my poc-unique.js)**: no-items-type ints: n=5000→31ms, 10000→104ms, 20000→403ms, 40000→**1004ms** (quadratic ~4×/2×); **20000 objects → 8116ms**; control `items:{type:integer}` 40000 → 8.85ms (safe O(n)). Agent C end-to-end on a real server: one 1MB body (~164k ints) froze it **27.7s**; 40k objects → 31.7s; concurrent requests all starved. ~50k objects in 1MB ⇒ minutes.
- **Impact**: single unauthenticated request → total event-loop starvation for tens of seconds to minutes (all clients blocked; Node single-threaded). `requestTimeout` can't fire during a synchronous loop; `bodyLimit` 1MB is ample. Confidence HIGH.
- **TRIPLE-CONFIRMED**: agent C (27.7s live), agent J (8.28s live for 228KB/20k objects; extrapolates ~28s ints / 155–180s objects at 1MB), and my poc-unique.js (20k objects=8.1s). Precondition is BROAD: any `uniqueItems:true` on an array of **objects** (very common "list of unique records") is O(n²), not just the no-items-type case — only SCALAR `items` type is safe (O(n) hash).
- J dead-ends (no process crash): deep-nested body stack overflow, recursive-$ref validate/serialize, async-handler RangeError all **caught → 500** (`validation.js:124-128`, `reply.js:538`, `wrap-thenable.js:41`); secure-json-parse proto scan is iterative BFS (linear, no overflow); fast-json-stringify anyOf linear; content-type/fqs/fmw linear or 16KB-capped.

### CANDIDATE C2 — [MED, Fastify-default] `removeAdditional:true` + composition silently strips valid data
- Fastify defaults AJV to `removeAdditional:true` (vanilla AJV = false). With `additionalProperties:false` combined with `allOf`/`oneOf`/`$ref`/`if-then`, AJV strips properties that ARE defined in the subschemas while still validating `ok:true` → data loss / situational bypass (e.g., an authz/conditional field defined only in a branch is dropped before the handler sees it). App-dependent impact. (C3 LOW: `coerceTypes:'array'` single-element unwrap / `null→""` massaging.)
- Note: agent C confirms **response serialization is a faithful whitelist — no info-leak beyond the developer's schema** (weakens my A1-sibling response-leak note to LOW; only the content-form mediaType-miss `false→JSON.stringify` corner remains, narrow).

### ⚠ A1 — [LOW / informational — DOCUMENTED behavior] Content-form body schema silently skips validation
- **Post-verification (agent V + my docs check)**: this is **explicitly documented** at `docs/Reference/Validation-and-Serialization.md:253` ("Other content types will not be validated") and a full ⚠ warning at `:260-274`. It requires the uncommon OpenAPI `content` body-schema form; under DEFAULT parsers it yields only an unvalidated STRING (a clean object needs a non-default parser e.g. @fastify/formbody). Downgraded to LOW/informational — real and reproducible, but intended/documented, not a novel zero-day. Kept here for completeness. Original analysis below.
- Sink: `lib/validation.js:174` — `const contentSchema = context[bodySchema][request.mediaType]`. For OpenAPI-style `schema.body.content = { 'application/json': {...} }`, `context[bodySchema]` is a plain object keyed by content-type (`validation.js:89-97`). Validator chosen by attacker-controlled `request.mediaType`. On key miss → `validatorFunction=null` → `validateParam(null)` returns `false` (no error) → **body validation fully skipped**.
- Attacker: `POST /route` with a `Content-Type` that HAS a parser but is NOT a content-map key. Default config: `text/plain` yields an unvalidated **string** body (weak). Escalation to unvalidated **object** body requires the app to have an object-producing parser for a non-listed type (urlencoded, vendor `+json`, catch-all `*`) — common in real apps.
- Precondition: route uses the `content` form of `schema.body` (less common). Plain `schema.body={type:'object'}` form is a function and NOT affected.
- Status: **CONFIRMED end-to-end** (my poc-a1.js): (1) `application/json` invalid body → 400 (validation runs); (2) `text/plain` → 200 unvalidated string; (3) custom `application/vnd.evil+json` object parser → 200 with full unvalidated OBJECT `{isAdmin:true,...}` (missing required `secret`, extra props NOT stripped). Clean mass-assignment/bypass when app has any object-producing parser for a non-listed type. Genuine core deviation: `validation.js:174` should 415 on an uncovered media type, not silently skip.
- **Sibling observation (response side, my read of `lib/schemas.js:145-208`)**: `getSchemaSerializer` for the content-form response schema ALSO silently returns `false` on a mediaType miss (no `*/*`), and reply.js `serialize()` then falls back to `JSON.stringify(data)` (reply.js:1069) — i.e., serializes WITHOUT the response schema's `additionalProperties` stripping → potential **info-leak of fields the schema would strip**. Also: if `ct.isValid===false` on a content-form status entry, it falls through to `return responseSchemaDef[statusCode]` (the map OBJECT) → reply calls it as a function → TypeError → 500. Both gated on app using content-form response schemas + a reachable content-type mismatch. Same root pattern as A1 (silent degrade instead of error). C to dig.

### DEAD END — Family F (trust-proxy / header injection)
trust-proxy implemented correctly. Spoofing `request.ip/host/protocol` works ONLY under `trustProxy:true` or numeric (documented footgun — matches Express, gates on `proxyFn(remoteAddr,0)`); subnet/function trust correctly blocks; no-trustProxy ignores XFF entirely. Response splitting blocked by Node (`ERR_INVALID_CHAR`→500). proxy-addr hop counting correct (my PoC agrees). No novel code defect. BLOCKED. (Residual: `ip`/`protocol` returned unvalidated → secondary-sink risk if app trusts it; config-dependent.)

### DEAD END — Family E (cross-request via shared state / races)
No HIGH cross-request leak in default config. Per-request Request/Reply freshly allocated; shared Context written only at registration; module caches (ContentType LRU, CTP FIFO, fmw constraint stores) hold only header-derived immutable values; reference-type req/reply decorators blocked (`decorate.js:69-73`). Empirical: 4000 interleaved + 2000 pipelined requests → 0 leaks. BLOCKED unless new mechanism. Adjacent promising: HTTP framing / QUERY-method (→ family G).

### DEAD END — Family D (prototype pollution)
Comprehensively hardened under default config: secure-json-parse (`protoAction/constructorAction:'error'`) blocks 13-payload bypass matrix; fast-querystring is flat (no nested pollution); params/headers/rfdc/toad-cache all safe. No core gadget. BLOCKED unless a new mechanism appears (e.g., a plugin deep-merge, out of core scope).

---

## Root-agent baseline recon (independent reads)

Established facts (to constrain/verify agent claims):
- **Defaults are standard & safe**: `onProtoPoisoning:'error'`, `onConstructorPoisoning:'error'`, `bodyLimit:1048576`, `maxParamLength:100`, `caseSensitive:true`, `allowUnsafeRegex:false`. AJV defaults: `coerceTypes:'array'`, `useDefaults:true`, `removeAdditional:true`, `allErrors:false`.
- **`lib/validation.js`** appears to be the current/fixed version (line 141 `'value' in ret` handles falsy coerced values). No obvious planted bug in the validate() flow itself.
- **`lib/reply.js`**: header/redirect/content-length paths look standard; raw CRLF in header values is rejected by Node's own `writeHead`/`setHeader`. content-length auto-correction at onSendEnd:677 keeps app value only for HEAD.
- **`lib/request.js`**: ip/host/hostname/port/protocol getters standard; trust-proxy getters gate `x-forwarded-host`/`-proto` on `proxyFn(socket.remoteAddress,0)` (immediate peer trusted). port regex is anchored (no ReDoS).
- **`lib/handle-request.js`**: pipeline standard (onRequest→body-parse→preValidation→validate→preHandler→handler).
- **Ground-truth PoC** (scratchpad/poc-proto.js): `secure-json-parse@4.1.0` with Fastify's default opts THROWS on `__proto__`, nested `__proto__`, `constructor`, nested `constructor.prototype`. `fast-querystring@1.1.2` is a FLAT parser — `__proto__[x]=1` becomes literal key `'__proto__[x]'`, no nested pollution. => easy proto-pollution routes are blocked by default; need a parser bypass or a non-default-parser gadget.

Additional ground-truth PoCs (scratchpad/poc-fjs.js):
- `fast-json-stringify@7.0.1` **escapes object keys and string values correctly** (`a":1,"injected` → `a\":1,\"injected`); `additionalProperties:false` strips extra props (no serialization info-leak via extra keys); `type:string` coerces via String(); `type:number` with non-numeric string **throws** `asNumber` error → becomes a 500 (serialization error caught in reply preSerializationHookEnd), NOT a process crash. => no direct JSON-injection or mass-leak via serializer.
- `url-sanitizer` decode-throw is caught in find-my-way `find()` (index.js:586-593 → `_onBadUrl`) → clean 400, not a crash. The `"null"`-injection in `safeDecodeURIComponent` is not reachable via normal flow (decodeURI pre-filters non-reserved %XX).
- `context.js`: shared per-route Context stores only registration-time config + schema-keyed WeakMaps of pure compiled fns; no per-request DATA written to shared state (cross-request leak via Context unlikely).

Implication: planted bug(s) likely live in **dependency logic or subtle core interactions** (content-type normalization/caching, find-my-way decoding/constraints, schema $id/$ref cross-route confusion, serialization, proxy-addr hop logic) rather than the obvious default-config surfaces. Task hint reinforces auditing dependency + dependency-of-dependency call interactions.

---

## Wave Log

### Wave 1 (in progress)
Launched 6 agents across families A–F.
