'use strict'
// Variant 3 — async validation continuation.  Same trigger as v1/v2 (handler
// returns an object under a non-JSON content-type -> reply.send throws
// FST_ERR_REP_INVALID_PAYLOAD_TYPE, NO header). The async part is validation
// (a custom async validator; a stock AJV $async schema behaves the same).
const path = require('path'); const { fork } = require('child_process'); const http = require('http')
const FASTIFY = path.join(__dirname, '..', '..', '..', 'fastify.js')
if (process.env.POC_ROLE === 'server') {
  const Fastify = require(FASTIFY)
  const app = Fastify({ logger: false })
  // custom ASYNC validator -> Fastify runs validation on the async path
  app.setValidatorCompiler(({ schema }) => async (data) => true)
  app.get('/report', {
    schema: { querystring: { type: 'object', properties: { q: { type: 'string' } } } }
  }, (req, reply) => { reply.type('text/csv'); return { rows: [1, 2, 3] } }) // object under text/csv
  app.listen({ port: 0, host: '127.0.0.1' }).then(() => process.send({ port: app.server.address().port })).catch(e => { console.error(e); process.exit(2) })
  return
}
console.log('=== Variant 3: async validation continuation ===')
const child = fork(__filename, [], { env: { ...process.env, POC_ROLE: 'server' }, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] })
let exited = false
child.on('message', ({ port }) => { console.log(`[harness] GET /report?q=x on :${port}`); http.get({ host: '127.0.0.1', port, path: '/report?q=x' }, r => r.resume()).on('error', e => console.log('[harness] socket:', e.code)) })
child.on('exit', code => { exited = true; console.log(`[harness] SERVER EXITED code=${code} => ${code !== 0 ? 'CRASH' : 'survived'}`); process.exit(code !== 0 ? 0 : 1) })
setTimeout(() => { if (!exited) { console.log('survived (not reproduced)'); child.kill('SIGKILL'); process.exit(1) } }, 5000)
