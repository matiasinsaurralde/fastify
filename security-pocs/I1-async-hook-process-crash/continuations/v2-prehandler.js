'use strict'
// Variant 2 — async preHandler/auth continuation.  Same trigger as v1/v3
// (handler returns an object under a non-JSON content-type -> reply.send throws
// FST_ERR_REP_INVALID_PAYLOAD_TYPE, NO header). The async part is a preHandler.
const path = require('path'); const { fork } = require('child_process'); const http = require('http')
const FASTIFY = path.join(__dirname, '..', '..', '..', 'fastify.js')
if (process.env.POC_ROLE === 'server') {
  const Fastify = require(FASTIFY)
  const app = Fastify({ logger: false })
  app.addHook('preHandler', async (req, reply) => { await Promise.resolve() })          // async auth (e.g. verifyJwt)
  app.get('/report', (req, reply) => { reply.type('text/csv'); return { rows: [1, 2, 3] } }) // object under text/csv
  app.listen({ port: 0, host: '127.0.0.1' }).then(() => process.send({ port: app.server.address().port })).catch(e => { console.error(e); process.exit(2) })
  return
}
console.log('=== Variant 2: async preHandler/auth continuation ===')
const child = fork(__filename, [], { env: { ...process.env, POC_ROLE: 'server' }, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] })
let exited = false
child.on('message', ({ port }) => { console.log(`[harness] GET /report on :${port}`); http.get({ host: '127.0.0.1', port, path: '/report' }, r => r.resume()).on('error', e => console.log('[harness] socket:', e.code)) })
child.on('exit', code => { exited = true; console.log(`[harness] SERVER EXITED code=${code} => ${code !== 0 ? 'CRASH' : 'survived'}`); process.exit(code !== 0 ? 0 : 1) })
setTimeout(() => { if (!exited) { console.log('survived (not reproduced)'); child.kill('SIGKILL'); process.exit(1) } }, 5000)
