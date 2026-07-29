'use strict'
/*
 * I1 variant "I-C2" — process crash with NO header and NO attacker data.
 * ---------------------------------------------------------------------------
 * The base I1 crash goes through an invalid response header, which invites the
 * "sanitize your input" framing. This variant removes headers and untrusted data
 * from the picture entirely, to show it's the same *framework* defect: a
 * send-time error that the sync path turns into a graceful 5xx becomes a whole-
 * process crash when it is reached through an async continuation.
 *
 * Setup (all ordinary):
 *   - an async `preHandler` (e.g. `await verifyJwt()`) — every app with auth has these
 *   - a CSV endpoint whose handler returns an object instead of a CSV string
 *     (a mundane bug / conditional branch). Returning an object under a non-JSON
 *     content-type makes `reply.send` throw FST_ERR_REP_INVALID_PAYLOAD_TYPE
 *     (reply.js:674) — nothing to do with headers or user input.
 *
 * Asymmetry demonstrated:
 *   - /export-plain    (no async hook)   -> the sync path's try/catch in
 *                                           handle-request.js `handler()` catches
 *                                           the throw -> graceful 5xx, server lives.
 *   - /export-guarded  (async preHandler)-> the handler + reply.send run inside
 *                                           the hook runner's discarded .then()
 *                                           continuation, outside that try/catch
 *                                           -> unhandledRejection -> process abort.
 *
 *   Run:  node poc-variant-no-header-crash.js
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

  // A CSV export handler that (by a common mistake) returns an OBJECT instead of
  // a CSV string. No request data is reflected anywhere; no headers are set from
  // input. Under the non-JSON content-type, reply.send cannot serialize it.
  const csvHandler = (req, reply) => {
    reply.type('text/csv')
    return { rows: [1, 2, 3] } // <-- object under text/csv -> FST_ERR_REP_INVALID_PAYLOAD_TYPE
  }

  // Route WITHOUT an async hook -> fully synchronous dispatch -> graceful 5xx.
  app.get('/export-plain', csvHandler)

  // Same handler, guarded by an async auth preHandler (ubiquitous) -> async path.
  app.get('/export-guarded', {
    preHandler: async (req, reply) => { await Promise.resolve() /* e.g. await verifyJwt(req) */ }
  }, csvHandler)

  app.listen({ port: 0, host: '127.0.0.1' })
    .then(() => process.send({ port: app.server.address().port }))
    .catch((e) => { console.error('server failed to start', e); process.exit(2) })
  return
}

// --------------------------------------------------------------------------
// PARENT ROLE: harness
// --------------------------------------------------------------------------
console.log('=== I-C2: process crash with NO header and NO attacker data ===\n')

const child = fork(__filename, [], {
  env: { ...process.env, POC_ROLE: 'server' },
  stdio: ['ignore', 'inherit', 'inherit', 'ipc']
})

let exited = false
let inFlight = ''

function get (port, p) {
  return new Promise((resolve) => {
    const r = http.get({ host: '127.0.0.1', port, path: p }, (res) => {
      res.resume(); res.on('end', () => resolve({ status: res.statusCode }))
    })
    r.on('error', (e) => resolve({ status: 'ERR', code: e.code }))
  })
}

child.on('message', async ({ port }) => {
  console.log(`[harness] server up on 127.0.0.1:${port}\n`)

  inFlight = '/export-plain'
  const a = await get(port, '/export-plain')
  console.log(`[harness] GET /export-plain    (no async hook)    -> ${a.status}${a.code ? ' ' + a.code : ''}   (sync path recovers -> graceful error, server lives)`)

  inFlight = '/export-guarded'
  console.log('[harness] GET /export-guarded  (async preHandler) -> sending...')
  const b = await get(port, '/export-guarded')
  console.log(`[harness]   -> ${b.status}${b.code ? ' ' + b.code : ''}   (server died mid-response)`)
})

child.on('exit', (code) => {
  exited = true
  console.log(`\n[harness] SERVER PROCESS EXITED  code=${code}  (crashed while handling ${inFlight})`)
  if (code !== 0) {
    console.log('\n==> Same handler, same return value, no headers, no untrusted data.')
    console.log('    WITHOUT the async hook -> graceful 5xx; WITH an async preHandler -> whole-process crash.')
    console.log('    The only variable is whether the send-time error was reached through an async continuation.')
    process.exit(0)
  } else {
    console.log('\n==> Not reproduced (server survived).')
    process.exit(1)
  }
})

setTimeout(() => {
  if (!exited) { console.log('[harness] server survived 5s — not reproduced'); child.kill('SIGKILL'); process.exit(1) }
}, 5000)
