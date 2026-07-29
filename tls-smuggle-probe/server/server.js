'use strict'
/*
 * uWebSockets.js target server for the smuggling parser-deviation probe.
 *
 * Starts BOTH:
 *   - an HTTPS listener via uWS.SSLApp  (TLS is terminated here, in uWS itself)
 *   - a plain HTTP listener via uWS.App (for comparing TLS vs plaintext results)
 *
 * TLS "termination" simply means uWS decrypts the TLS stream and feeds the
 * resulting plaintext bytes to its OWN HTTP/1.1 parser — the same parser the
 * plain-HTTP app uses. So the probe's parser-deviation results should match on
 * both ports; that is exactly the point the probe demonstrates.
 *
 * Env:
 *   HTTP_PORT (default 3000), TLS_PORT (default 3443), HOST (default 127.0.0.1)
 *   TLS_KEY / TLS_CERT (default ./certs/key.pem, ./certs/cert.pem)
 */
const uWS = require('uWebSockets.js')
const path = require('path')
const fs = require('fs')

const HOST = process.env.HOST || '127.0.0.1'
const HTTP_PORT = Number(process.env.HTTP_PORT || 3000)
const TLS_PORT = Number(process.env.TLS_PORT || 3443)
const KEY = process.env.TLS_KEY || path.join(__dirname, 'certs', 'key.pem')
const CERT = process.env.TLS_CERT || path.join(__dirname, 'certs', 'cert.pem')

// One handler used for every method/route. It reads the whole body (so uWS's
// framing decisions are exercised) then replies with a summary.
function handler (res, req) {
  // req is only valid synchronously — capture what we need now.
  const method = req.getMethod()
  const url = req.getUrl()
  const cl = req.getHeader('content-length')
  const te = req.getHeader('transfer-encoding')

  res.aborted = false
  res.onAborted(() => { res.aborted = true })

  const reply = (bodyLen) => {
    if (res.aborted) return
    res.cork(() => {
      res.writeStatus('200 OK')
      res.writeHeader('x-served-by', 'uwebsockets.js')
      res.writeHeader('content-type', 'text/plain')
      res.end(`OK method=${method} url=${url} cl="${cl}" te="${te}" bodyBytes=${bodyLen}`)
    })
  }

  // Bodyless methods with no framing headers: reply immediately (uWS may not
  // deliver an onData for these).
  const hasBody = cl !== '' || te !== ''
  if (!hasBody && (method === 'get' || method === 'head' || method === 'delete' || method === 'options')) {
    reply(0)
    return
  }

  let total = 0
  res.onData((chunk, isLast) => {
    if (chunk && chunk.byteLength) total += chunk.byteLength
    if (isLast) reply(total)
  })
}

function attach (app) {
  app.any('/*', handler)
  return app
}

// ---- HTTPS (TLS terminated by uWS) ----
if (!fs.existsSync(KEY) || !fs.existsSync(CERT)) {
  console.error(`[uWS] missing TLS material: ${KEY} / ${CERT}`)
  console.error('      run  ./gen-certs.sh  first (or set TLS_KEY / TLS_CERT).')
  process.exit(1)
}

attach(uWS.SSLApp({ key_file_name: KEY, cert_file_name: CERT }))
  .listen(HOST, TLS_PORT, (token) => {
    if (token) console.log(`[uWS] HTTPS  (TLS terminated by uWS) listening on https://${HOST}:${TLS_PORT}`)
    else { console.error(`[uWS] FAILED to listen on TLS ${TLS_PORT}`); process.exit(1) }
  })

// ---- HTTP (plaintext, for comparison) ----
attach(uWS.App())
  .listen(HOST, HTTP_PORT, (token) => {
    if (token) console.log(`[uWS] HTTP   (plaintext)              listening on http://${HOST}:${HTTP_PORT}`)
    else { console.error(`[uWS] FAILED to listen on HTTP ${HTTP_PORT}`); process.exit(1) }
  })

console.log('[uWS] ready — Ctrl-C to stop')
