# TLS request-smuggling parser-deviation probe (+ uWebSockets.js target)

A **TLS-capable** sibling of the plaintext HTTP/1.1 smuggling probe, plus a
self-contained **uWebSockets.js** target (HTTP **and** HTTPS) so you can run the
whole thing end-to-end locally.

It answers the question *"does the smuggling probe still work over TLS?"* with a
runnable demonstration: the probe speaks raw HTTP/1.1 through a real TLS 1.3
tunnel to a uWS `SSLApp`, and produces **the same** parser-deviation results as
it does over plaintext.

> ⚠️ **Authorized testing only.** Everything here targets `127.0.0.1`. Point it
> only at servers you own or are authorized to test.

## TL;DR — does TLS change anything?

- **The vulnerability: no.** HTTP framing (Content-Length vs Transfer-Encoding,
  chunked, bare-LF…) is parsed **after** TLS is decrypted. uWS terminates TLS
  and feeds the plaintext bytes to the *same* HTTP parser it uses for cleartext,
  so the deviations are identical. The E2E run below proves it (TLS ≡ plaintext).
- **The probe: yes, two things.**
  1. You must wrap the socket in TLS and accept the self-signed cert (`-k`).
  2. **ALPN.** A TLS handshake can negotiate **HTTP/2**, whose framing is
     completely different — the HTTP/1.1 CL/TE payloads do not apply. This probe
     **pins ALPN to `http/1.1`** by default and **detects and stops on h2**. (uWS
     is HTTP/1.1-only, so it negotiates no ALPN and the payloads apply — but a
     server behind nginx/an ALB may speak h2, which needs an h2-downgrade probe.)
- **In real deployments** TLS is usually terminated at the edge (nginx/ALB/CDN)
  and the smuggling-relevant hop (edge → uWS backend) is frequently cleartext
  HTTP/1.1 anyway. So testing uWS over plaintext is often the faithful backend
  representation; the deviation is a property of uWS, not the transport.

## Layout

```
tls-smuggle-probe/
├── smuggle_probe_tls.go     the probe (Go, stdlib only: crypto/tls + net)
├── go.mod
├── run-e2e.sh               one-shot: certs → boot server → probe TLS + plaintext
├── README.md
└── server/
    ├── server.js            uWebSockets.js: uWS.SSLApp (HTTPS) + uWS.App (HTTP)
    ├── gen-certs.sh         openssl self-signed cert for localhost
    └── package.json         dep: uNetworking/uWebSockets.js
```

## Requirements

- Go ≥ 1.21 (built with 1.24), Node ≥ 16, OpenSSL, and `npm`.
- The probe uses **only the Go standard library** — no `go get` needed.

## Quick start (E2E)

```bash
cd tls-smuggle-probe
( cd server && npm install )     # installs uWebSockets.js (native, prebuilt binaries)
./run-e2e.sh
```

`run-e2e.sh` generates a cert, boots the uWS server (HTTPS on :3443, HTTP on
:3000), runs the probe against **both**, and tears down.

## Point it at your own server

```bash
# your uWS SSLApp over TLS (skip cert verification for self-signed):
go run smuggle_probe_tls.go -k https://localhost:3000

# force HTTP/1.1 if the endpoint might offer h2 (recommended when unsure):
go run smuggle_probe_tls.go -k -alpn http/1.1 https://your-host:443

# plaintext still works (same tool):
go run smuggle_probe_tls.go http://localhost:3000

# see the raw bytes exchanged for every test:
go run smuggle_probe_tls.go -k -v https://localhost:3443
```

Note: your original command, `-k http://localhost:3000`, targets **plaintext**
(`http://`), so `-k` (skip-cert-verify) is a no-op there — it only matters once
you switch the URL to `https://`.

### Flags

| flag | meaning |
|------|---------|
| `-k`, `-insecure` | skip TLS certificate verification (self-signed certs) |
| `-alpn p1,p2` | ALPN protocols to offer (default `http/1.1`; use `h2,http/1.1` to let a server pick h2) |
| `-timeout d` | per-request read timeout for the time-based tests (default `3s`) |
| `-v` | dump the raw request/response bytes for each test |

## What the tests probe

| test | what it sends | reading the result |
|------|----------------|--------------------|
| `baseline-get` / `baseline-post-cl` | well-formed GET / POST | sanity — should be `200` |
| `te-chunked` | `Transfer-Encoding: chunked`, no CL | does the parser support chunked request bodies? |
| `clte-A` | CL+TE, chunked body complete, CL says more | **fast⇒used TE, timeout⇒used CL**, `400`⇒rejects both |
| `clte-B` | CL+TE, chunked body incomplete, CL complete | **fast⇒used CL, timeout⇒used TE** |
| `dup-cl` | two conflicting `Content-Length` | RFC says reject (`400`); `200` = risky |
| `te-trailing-space` | `Transfer-Encoding: chunked·` | lenient value parsing? |
| `te-space-before-colon` | `Transfer-Encoding·: chunked` | lenient name parsing? |
| `te-xchunked` | `Transfer-Encoding: xchunked` | unknown coding accepted? |
| `te-double` | two `Transfer-Encoding` headers | which wins / accepted? |
| `bare-lf` | headers ended with bare `\n` | CRLF-strict or lenient? |

The two `clte-*` tests use a **timing oracle**: with both CL and TE present, one
payload is complete only under the TE interpretation and the other only under
CL. A *fast* reply vs a *timeout* tells you which length the server honored —
without needing the front-end half of the pair.

`clte` tests returning `400` mean the server rejects CL+TE outright (RFC 9112
§6.1 — the safe behavior).

## E2E result (this repo, Node 22, uWebSockets.js v20.51.0)

`ALPN=""` on the TLS port confirms uWS negotiates **no HTTP/2** — so the
payloads apply, and the TLS and plaintext columns match test-for-test:

```
################## HTTPS (TLS) ##################
transport: TLS 1.3, cipher=0x1301, ALPN=""
  (no ALPN negotiated -> server will speak HTTP/1.1; payloads apply)

  baseline-get           "HTTP/1.1 200 OK"                          (436µs)
  baseline-post-cl       "HTTP/1.1 200 OK"                          (196µs)
  te-chunked             "HTTP/1.1 200 OK"                          (145µs)
  clte-A                 "HTTP/1.1 400 Bad Request"                 (36µs)
  clte-B                 "HTTP/1.1 400 Bad Request"                 (66µs)
  dup-cl                 "HTTP/1.1 200 OK"                          (145µs)
  te-trailing-space      "HTTP/1.1 200 OK"                          (117µs)
  te-space-before-colon  "HTTP/1.1 400 Bad Request"                 (79µs)
  te-xchunked            "HTTP/1.1 200 OK"                          (147µs)
  te-double              "HTTP/1.1 200 OK"                          (120µs)
  bare-lf                "HTTP/1.1 505 HTTP Version Not Supported"  (62µs)

################## HTTP (plaintext) ##################  ← identical verdicts
  baseline-get           "HTTP/1.1 200 OK"
  …
  dup-cl                 "HTTP/1.1 200 OK"
  te-xchunked            "HTTP/1.1 200 OK"
  bare-lf                "HTTP/1.1 505 HTTP Version Not Supported"
```

Interpretation for this uWS build (same on both transports):

- Rejects `Content-Length`+`Transfer-Encoding` together → **good** (RFC-compliant).
- Accepts chunked request bodies.
- **Accepts duplicate `Content-Length`** → deviation; risky if a stricter proxy sits in front.
- **Accepts** `Transfer-Encoding: chunked␠` (trailing space), `xchunked`, and doubled TE → lenient value parsing; potential desync vs a proxy that parses these differently.
- Rejects a space **before** the colon, and rejects bare-LF → strict there.

None of these is by itself a smuggle — exploitability depends on the front-end
you pair uWS with. The point demonstrated here is that **the probe works over
TLS and the results do not change**.

## Verifying what your target negotiates (before trusting the probe)

```bash
echo | openssl s_client -connect HOST:PORT -alpn h2,http/1.1 2>/dev/null | grep -i ALPN
# or
curl -kv --http1.1 https://HOST:PORT 2>&1 | grep -i 'ALPN\|HTTP/'
```

If you see `h2`, switch to an h2-downgrade probe; the HTTP/1.1 payloads here do
not apply (the tool detects this and stops with a message).

## Extending to HTTP/2 downgrade smuggling

Out of scope for this HTTP/1.1 tool. If your edge is HTTP/2 → HTTP/1.1, the
interesting classes are `h2.CL` / `h2.TE` and header/`:path` injection carried
in HTTP/2 frames that the downgrade fails to sanitize. That needs an
HTTP/2-framing client (e.g. Go's `golang.org/x/net/http2` with a custom framer),
not a raw byte-blaster. Happy to add an `-http2` mode if useful.
