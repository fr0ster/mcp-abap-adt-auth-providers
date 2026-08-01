import * as net from 'node:net';

export async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (typeof address === 'object' && address?.port) {
        const port = address.port;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error('Failed to acquire a port')));
      }
    });
  });
}

export async function canListenOnLocalhost(): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.listen(0, '127.0.0.1', () => {
      server.close(() => resolve(true));
    });
  });
}

/**
 * Whether a login in this test could own `port` — and therefore whether
 * asserting that it released the port means anything.
 *
 * A release assertion is a claim about our own cleanup. When an unrelated
 * process already holds the port, the login fails at the probe, never binds
 * anything, and cannot release anything: the port is still held afterwards,
 * the code is behaving exactly as it should, and the assertion fails anyway.
 * That is a test reporting on what else is running on the machine.
 *
 * So the gate is placed *before* the login rather than the assertion being
 * widened until it always passes — a `toBe(true)` relaxed into "free or held"
 * would also pass when our own cleanup leaked, which is the one thing these
 * cases exist to catch.
 */
export async function canOwnPort(
  port: number,
  context: string,
): Promise<boolean> {
  const free = await new Promise<boolean>((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, () => probe.close(() => resolve(true)));
  });
  if (!free) {
    console.warn(
      `⚠️  Port ${port} is held by another process — skipping the port-release ` +
        `assertions in "${context}". A login that never bound the socket cannot ` +
        'release it; the remaining assertions in this case still run.',
    );
  }
  return free;
}
