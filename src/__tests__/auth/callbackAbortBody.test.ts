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
  let closed = false;
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
        // A half-open client sees the server's FIN as 'end', a reset as 'close'.
        const seen = () => {
          closed = true;
        };
        stalled.on('end', seen);
        stalled.on('close', seen);
        await new Promise((resolve) => stalled.once('connect', resolve));
        // Complete headers, a body promised and never finished.
        stalled.write(
          // A Host the transport answers for (spec §6a1): else it is
          // refused before the body parser, and nothing stalls.
          'POST /callback HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n' +
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
  // The server destroys an unfinished request: the client sees the close.
  // Bounded here by the scenario itself, never by the package.
  for (let i = 0; i < 100 && !closed; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  process.stdout.write(JSON.stringify({ outcome, free, closed }));
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
      closed: boolean;
    };
    expect(report.closed).toBe(true);
    expect(report.free).toBe(true);
    expect(report.outcome).not.toBe('resolved');
  }, 60_000);
});

/**
 * A complete request the route has not answered yet is still being answered
 * when the scope ends. Its socket is let go of (no hold on the process) but
 * not destroyed (a late answer is still delivered).
 */
const answering = (out: string, late: boolean) => `
const net = require('node:net');
const { runCallbackScope, sendText } = require(${JSON.stringify(join(out, 'auth', 'callbackServer.js'))});
(async () => {
  const controller = new AbortController();
  let port;
  let client;
  let pending;
  let received = '';
  await runCallbackScope(
    { port: 0, signal: controller.signal },
    (app) => {
      app.get('/slow', (_req, res) => { pending = res; });
    },
    async (srv) => {
      port = srv.port;
      const waiting = srv.waitForResult();
      client = net.connect({ port, host: '127.0.0.1' });
      client.on('data', (chunk) => { received += chunk.toString('latin1'); });
      client.on('error', () => undefined);
      await new Promise((resolve) => client.once('connect', resolve));
      client.write('GET /slow HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n\\r\\n');
      // The request is complete and the route has not answered.
      await new Promise((resolve) => setTimeout(resolve, 200));
      if (!${late}) client.unref();
      setImmediate(() => controller.abort());
      return await waiting;
    },
  ).catch(() => undefined);
  const free = await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
  if (${late}) {
    await new Promise((resolve) => {
      client.on('close', resolve);
      sendText(pending, 200, 'answered late');
    });
  }
  process.stdout.write(JSON.stringify({ free, received }));
  // No process.exit: the child must end on its own.
})();
`;

describe('a request still unanswered when the scope ends', () => {
  const run = (late: boolean) =>
    spawnSync(process.execPath, ['-e', answering(compiledSources(), late)], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, NODE_PATH: join(root, 'node_modules') },
      // The test's own bound on the child: a child kept alive is the failure.
      timeout: 15_000,
      killSignal: 'SIGKILL',
    });

  it('holds no process: an unanswered connection does not keep it alive', () => {
    const child = run(false);
    expect(child.signal).toBeNull();
    expect(child.status).toBe(0);
    expect(JSON.parse(child.stdout).free).toBe(true);
  }, 60_000);

  it('is not destroyed: the late answer still reaches the client', () => {
    const child = run(true);
    expect(child.signal).toBeNull();
    expect(child.status).toBe(0);
    const { free, received } = JSON.parse(child.stdout) as {
      free: boolean;
      received: string;
    };
    expect(free).toBe(true);
    expect(received).toContain('200 OK');
    expect(received).toContain('answered late');
  }, 60_000);
});
