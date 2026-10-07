/**
 * "A lingering client holds neither the port nor the process" (Task 23 fix
 * round 1). A client that never closes its side — `allowHalfOpen`, a request
 * left half-sent, so Node's own `close()` does not count it idle — is still
 * connected when the scope ends. The scope settles, the port is bindable,
 * and the process exits on its own: the connection was ended and let go
 * (`unref`), never waited for. Run in a child process, bounded only by this
 * test's own `timeout` on the child.
 */

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { compiledSources } from '../helpers/plainNode';

const root = join(__dirname, '..', '..', '..');

const scenario = (out: string) => `
const net = require('node:net');
const http = require('node:http');
const { withBrowserCallbackServer } = require(${JSON.stringify(join(out, 'auth', 'callbackServer.js'))});
(async () => {
  let port;
  let lingering;
  const result = await withBrowserCallbackServer(
    { port: 0 },
    async (srv) => {
      port = srv.port;
      const waiting = srv.waitForResult();
      lingering = net.connect({ port, host: '127.0.0.1', allowHalfOpen: true });
      lingering.on('data', () => undefined);
      lingering.on('end', () => undefined);
      await new Promise((resolve) => lingering.once('connect', resolve));
      // Half a request: the connection is busy, not idle, to Node's close().
      lingering.write('GET / HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n');
      await new Promise((resolve) => setImmediate(resolve));
      // The client's own side holds nothing; only the server's could.
      lingering.unref();
      http.get({ port, host: '127.0.0.1', path: '/callback?code=c1', agent: false }, (r) => r.resume());
      return await waiting;
    },
  );
  const free = await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
  process.stdout.write(JSON.stringify({ result, free, stillOpen: !lingering.destroyed }));
  // No process.exit: the child must end on its own.
})();
`;

describe('a lingering client after the scope', () => {
  it('holds neither the port nor the process', () => {
    const out = compiledSources();
    const child = spawnSync(process.execPath, ['-e', scenario(out)], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, NODE_PATH: join(root, 'node_modules') },
      // The test's own bound on the child: a child kept alive is the failure.
      timeout: 15_000,
    });
    expect(child.signal).toBeNull();
    expect(child.status).toBe(0);
    expect(JSON.parse(child.stdout)).toEqual({
      result: 'c1',
      free: true,
      stillOpen: true,
    });
  }, 60_000);
});
