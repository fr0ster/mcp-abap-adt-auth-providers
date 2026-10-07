/**
 * A SAML POST whose headers arrived and whose body never finishes is
 * outstanding to the server (`request` was emitted) yet stalls in
 * `express.urlencoded`. Aborting the login must still let the process go:
 * the scope settles `aborted`, the port is bindable, and the child exits on
 * its own. Run in a child process, bounded only by this test's own timeout.
 */

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { compiledSources } from '../helpers/plainNode';

const root = join(__dirname, '..', '..', '..');

const scenario = (out: string) => `
const net = require('node:net');
const { withSamlCallbackServer } = require(${JSON.stringify(join(out, 'auth', 'saml2Auth.js'))});
(async () => {
  const controller = new AbortController();
  let port;
  let stalled;
  let outcome;
  try {
    await withSamlCallbackServer(
      { port: 0, signal: controller.signal },
      async (srv) => {
        port = srv.port;
        const waiting = srv.waitForResult();
        stalled = net.connect({ port, host: '127.0.0.1', allowHalfOpen: true });
        stalled.on('data', () => undefined);
        stalled.on('error', () => undefined);
        await new Promise((resolve) => stalled.once('connect', resolve));
        // Complete headers, a body promised and never finished.
        stalled.write(
          'POST /callback HTTP/1.1\\r\\nHost: x\\r\\n' +
          'Content-Type: application/x-www-form-urlencoded\\r\\n' +
          'Content-Length: 1000\\r\\n\\r\\nSAMLResponse=abc',
        );
        await new Promise((resolve) => setTimeout(resolve, 100));
        // The client's own side holds nothing; only the server's could.
        stalled.unref();
        setImmediate(() => controller.abort());
        return await waiting;
      },
    );
    outcome = 'resolved';
  } catch (error) {
    outcome = error && error.code ? String(error.code) : 'rejected';
  }
  const free = await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
  process.stdout.write(JSON.stringify({ outcome, free }));
  // No process.exit: the child must end on its own.
})();
`;

describe('a SAML POST with an unfinished body, the login aborted', () => {
  it('settles, frees the port and lets the process exit', () => {
    const out = compiledSources();
    const child = spawnSync(process.execPath, ['-e', scenario(out)], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, NODE_PATH: join(root, 'node_modules') },
      // The test's own bound on the child: a child kept alive is the failure.
      timeout: 15_000,
      killSignal: 'SIGKILL',
    });
    expect(child.signal).toBeNull();
    expect(child.status).toBe(0);
    const report = JSON.parse(child.stdout) as {
      outcome: string;
      free: boolean;
    };
    expect(report.free).toBe(true);
    expect(report.outcome).not.toBe('resolved');
  }, 60_000);
});
