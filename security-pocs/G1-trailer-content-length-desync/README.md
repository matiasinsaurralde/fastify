# G1 — Response-framing desync: `Content-Length` + `Transfer-Encoding: chunked` on one response

| | |
|---|---|
| **Severity** | **MEDIUM** (real-world exploit needs a non-strict downstream intermediary) |
| **Class** | HTTP response smuggling / framing desynchronization |
| **CWE** | CWE-444 (Inconsistent Interpretation of HTTP Requests / "Request Smuggling") |
| **Component** | `lib/reply.js` (`onSendEnd` trailer/CL handling) × `lib/head-route.js` — Fastify core |
| **Auth required** | No |
| **Affected** | `fastify@5.10.0` |

## Summary

When a route uses `reply.trailer()`, Fastify switches the response to
`Transfer-Encoding: chunked` but does **not** remove a `Content-Length` header
set by another code path. The clearest trigger is the **auto-generated HEAD
route**: its `onSend` handler sets `Content-Length`, and the trailer logic then
adds `Transfer-Encoding: chunked` without clearing it.

The result is a response carrying **both** `Content-Length` and
`Transfer-Encoding: chunked` — a violation of RFC 9112 §6.1 and a classic
response-framing desynchronization primitive. A downstream intermediary that
frames by `Content-Length` reads that many bytes of the *following* response as
this response's body, misaligning every message boundary after it (response
smuggling, cache poisoning, cross-client response bleed).

## Attacker model & preconditions

- Remote client, no authentication (the attacker just uses the `HEAD` method;
  the auto-HEAD route is on by default via `exposeHeadRoutes`).
- Precondition (app side): a `GET` route uses the documented `reply.trailer()`
  feature.
- Real-world exploitation additionally requires a downstream hop that is not
  strictly RFC-compliant for HEAD (i.e. it honors `Content-Length` / reads a
  HEAD body) — hence MEDIUM rather than HIGH.

## Root-cause analysis

`lib/head-route.js` — the auto-HEAD onSend handler sets `Content-Length`:

```js
// lib/head-route.js — headRouteOnSendHandler
const size = '' + Buffer.byteLength(payload)
reply.header('content-length', size)   // HEAD advertises the would-be body length
done(null, null)
```

`lib/reply.js` — `onSendEnd` adds chunked/trailer framing but never deletes a
pre-existing `Content-Length`, and the Content-Length reconciliation is **skipped
whenever trailers are present**:

```js
// lib/reply.js — onSendEnd
if (reply[kReplyTrailers] !== null) {
  // …
  reply.header('Transfer-Encoding', 'chunked')   // adds TE, but leaves Content-Length in place
  reply.header('Trailer', header.trim())
}
// …
if (reply[kReplyTrailers] === null) {            // <-- CL reconciliation ONLY when no trailers
  const contentLength = reply[kReplyHeaders]['content-length']
  if (!contentLength || /* mismatch */ ) {
    reply[kReplyHeaders]['content-length'] = '' + Buffer.byteLength(payload)
  }
}
safeWriteHead(reply, statusCode)                 // emits BOTH headers to the wire
```

So for `HEAD` on a trailer-using `GET` route, both `Content-Length` and
`Transfer-Encoding: chunked` reach the socket.

## Exploit chain

```
GET route uses reply.trailer('x-checksum', …)        (exposeHeadRoutes default -> HEAD /data exists)

Attacker (unauth):  HEAD /data
Fastify emits:
    HTTP/1.1 200 OK
    content-length: 7
    transfer-encoding: chunked
    trailer: x-checksum
    <empty body>

A CL-framing downstream proxy reads 7 bytes AFTER the headers as the HEAD "body".
On a keep-alive connection those 7 bytes are the start of the NEXT response
("HTTP/1."), so every subsequent response boundary is shifted -> response
smuggling / cache poisoning / cross-client bleed.
```

## How to run

```bash
cd security-pocs/G1-trailer-content-length-desync
node poc.js
```

The PoC starts a real server with a trailer-using `GET /data`, then sends a
`GET` (to show correct chunked-only framing) and a `HEAD` (to show the bug), and
prints the raw response bytes.

### Expected output

```
=== G1 PoC: Content-Length + Transfer-Encoding response desync ===

--- GET /data (correct: chunked only) ---
HTTP/1.1 200 OK\r\n
content-type: text/plain; charset=utf-8\r\n
transfer-encoding: chunked\r\n
trailer: x-checksum\r\n
…
7\r\n
hello!!\r\n
0\r\n
x-checksum: abc123\r\n
\r\n

--- HEAD /data (BUG: Content-Length AND Transfer-Encoding) ---
HTTP/1.1 200 OK\r\n
content-type: text/plain; charset=utf-8\r\n
content-length: 7\r\n
transfer-encoding: chunked\r\n
trailer: x-checksum\r\n
…

HEAD response has Content-Length?        true
HEAD response has Transfer-Encoding?     true
BOTH present (RFC 9112 s6.1 violation)?  true

==> VULNERABLE: the HEAD response is ambiguously framed.
```

Contrast the `GET` (chunked only, correct) with the `HEAD` (both headers).

## Impact

- Ambiguous response framing enables HTTP response smuggling / desync against a
  vulnerable intermediary: cache poisoning, serving one client another client's
  response, or request/response queue poisoning on shared keep-alive
  connections.
- A fully RFC-compliant proxy ignores `Content-Length`/`Transfer-Encoding` for
  HEAD, which is why this is rated MEDIUM; but the emitted bytes are
  spec-violating regardless.

## Related (documented in `../../findings.md`)

- **G2** — caller-set `Content-Length` + `reply.trailer()` on a non-HEAD `GET`
  produces the same CL+TE combination with a *real* chunked body.
- **G3** — `reply.trailer()` on a 204/304 → `ERR_HTTP_TRAILER_INVALID` → 500
  with malformed framing (broken endpoint, not a crash).
- Request-side smuggling was tested and found **safe** (Node/llhttp frames
  request bodies; Fastify drains unread bodies or sets `connection: close`).

## Suggested remediation

In `onSendEnd`, when switching to trailer/chunked framing, delete any existing
`Content-Length`:

```js
if (reply[kReplyTrailers] !== null) {
  reply.removeHeader('content-length')            // <-- add this
  reply.header('Transfer-Encoding', 'chunked')
  reply.header('Trailer', header.trim())
}
```

## References

- `lib/reply.js` — `onSendEnd` (trailer framing + the `kReplyTrailers === null`
  gate on Content-Length reconciliation).
- `lib/head-route.js` — `headRouteOnSendHandler` (sets `Content-Length`).
- RFC 9112 §6.1 (a message must not contain both `Content-Length` and
  `Transfer-Encoding`).
