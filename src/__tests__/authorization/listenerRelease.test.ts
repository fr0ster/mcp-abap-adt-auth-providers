/**
 * Release before settle (Task 30f's cases, spec §6d.3.5), for the composed
 * listener: an aborted login whose connections are still open lets the
 * process go — a POST whose body never finishes is destroyed, an idle
 * keep-alive connection or one with half a request is ended and
 * unreferenced — the open settles, the
 * port binds, and the child exits on its own. Run in a child process,
 * bounded only by this test's own timeout.
 */

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { compiledSources } from '../helpers/plainNode';

const root = join(__dirname, '..', '..', '..');

/** `client` is what the scenario does on its own socket once armed. */
const scenario = (out: string, client: string) => `
const net = require('node:net');
const { loopback4 } = require(${JSON.stringify(join(out, 'authorization', 'transport', 'index.js'))});
const { samlResponse } = require(${JSON.stringify(join(out, 'authorization', 'protocol', 'index.js'))});
(async () => {
  const controller = new AbortController();
  const protocol = samlResponse();
  let port;
  let socket;
  let closed = false;
  let outcome;
  try {
    await loopback4({ port: 0 }).open(
      {
        signal: controller.signal,
        paste: protocol.paste,
        callbackMethods: protocol.callbackMethods,
        endpoint: '/callback',
      },
      async (channel) => {
        port = Number(new URL(channel.redirectUri).port);
        const waiting = channel.arm(protocol.begin('')).answer();
        socket = net.connect({ port, host: '127.0.0.1', allowHalfOpen: true });
        socket.on('data', () => undefined);
        socket.on('error', () => undefined);
        // A half-open client sees the server's FIN as 'end', a reset as 'close'.
        const seen = () => { closed = true; };
        socket.on('end', seen);
        socket.on('close', seen);
        await new Promise((resolve) => socket.once('connect', resolve));
        ${client}
        await new Promise((resolve) => setTimeout(resolve, 100));
        // The client's own side holds nothing; only the server's could.
        socket.unref();
        setImmediate(() => controller.abort());
        return await waiting;
      },
    );
    outcome = 'resolved';
  } catch (error) {
    outcome = error && error.error && error.error.facts ? error.error.facts.outcome : 'rejected';
  }
  const free = await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
  });
  // Bounded here by the scenario itself, never by the package.
  for (let i = 0; i < 100 && !closed; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  process.stdout.write(JSON.stringify({ outcome, free, closed }));
  // No process.exit: the child must end on its own.
})();
`;

function run(client: string) {
  const child = spawnSync(
    process.execPath,
    ['-e', scenario(compiledSources(), client)],
    {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, NODE_PATH: join(root, 'node_modules') },
      // The test's own bound on the child: a child kept alive is the failure.
      timeout: 15_000,
      killSignal: 'SIGKILL',
    },
  );
  expect(child.signal).toBeNull();
  expect(child.status).toBe(0);
  return JSON.parse(child.stdout) as {
    outcome: string;
    free: boolean;
    closed: boolean;
  };
}

describe('the composed listener lets go of its connections at the abort', () => {
  it('a POST with an unfinished body: destroyed; the open settles aborted, the port is free, the process exits', () => {
    const report = run(`
        socket.write(
          'POST /callback HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n' +
          'Content-Type: application/x-www-form-urlencoded\\r\\n' +
          'Content-Length: 1000\\r\\n\\r\\nSAMLResponse=abc',
        );`);
    expect(report).toEqual({ outcome: 'aborted', free: true, closed: true });
  }, 60_000);

  it('an idle keep-alive connection after a refused request: ended; the process exits', () => {
    const report = run(`
        socket.write(
          'GET /callback?RelayState=x HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n' +
          'Connection: keep-alive\\r\\n\\r\\n',
        );`);
    expect(report).toEqual({ outcome: 'aborted', free: true, closed: true });
  }, 60_000);

  it('a lingering client with half a request (headers unfinished): ended and let go; the process exits', () => {
    // Not idle to Node's own close(): only the listener's release ends it.
    const report = run(`
        socket.write('GET / HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n');`);
    expect(report).toEqual({ outcome: 'aborted', free: true, closed: true });
  }, 60_000);

  it('a paused client pipelining 10000 requests: its pending answers hold nothing; the process exits', () => {
    // A pending write ignores unref(): only closing or destroying the
    // connection lets the process go (review m1). The client reads nothing.
    const report = run(`
        socket.removeAllListeners('data');
        socket.pause();
        const one = 'GET / HTTP/1.1\\r\\nHost: 127.0.0.1:' + port + '\\r\\n\\r\\n';
        socket.write(one.repeat(10000));`);
    expect(report.outcome).toBe('aborted');
    expect(report.free).toBe(true);
  }, 60_000);
});
