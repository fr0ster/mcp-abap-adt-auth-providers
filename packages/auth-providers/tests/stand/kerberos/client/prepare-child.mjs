// The SPNego suite's child harness: one prepare() in a Kerberos environment
// of the suite's choosing — no ticket, or a KDC that does not answer — given
// as this process's environment (KRB5CCNAME, KRB5_CONFIG), so the suite never
// writes its own.
//
//   node prepare-child.mjs <auth-providers dir> <auth-spnego-gssapi dir> \
//     <mechanism> <servicePrincipal>
//
// Loads both built packages (dist/) from the container's copies, composes
// SpnegoAuthProvider with gssapiTokenSource, calls prepare() and prints one
// JSON line: { ok: true }, or { ok: false, kind, variant, facts } of the
// refusal, and the provider's log lines — for the suite to assert, and to
// check that no token reached them.
import { createRequire } from 'node:module';
import path from 'node:path';

const [providersDir, gssapiDir, mechanism, servicePrincipal] =
  process.argv.slice(2);
const require = createRequire(import.meta.url);
const { SpnegoAuthProvider } = require(path.join(providersDir, 'dist'));
const { gssapiTokenSource } = require(path.join(gssapiDir, 'dist'));

const logs = [];
const record =
  (level) =>
  (...args) =>
    logs.push([level, ...args]);
const logger = {
  debug: record('debug'),
  info: record('info'),
  warn: record('warn'),
  error: record('error'),
};

const provider = new SpnegoAuthProvider({
  servicePrincipal,
  tokenSource: gssapiTokenSource({ mechanism }),
  logger,
});
const outcome = await provider.prepare();
const answer = outcome.ok
  ? { ok: true }
  : {
      ok: false,
      kind: outcome.refusal.kind,
      variant: outcome.refusal.variant,
      facts: outcome.refusal.facts,
    };
process.stdout.write(`${JSON.stringify({ ...answer, logs })}\n`);
