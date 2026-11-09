// Runs `node --test` over the compiled tests in `.test-build/`, on every platform the
// package supports.
//
//   node tools/run-tests.mjs [--env NAME=VALUE]... [node --test options]... [paths]...
//
// - With no path, it runs every `*.test.js` under `.test-build/`. Finding none is an error:
//   `node --test` with a pattern that matches nothing exits 0, so a broken build would pass.
// - A path is a `*.test.js` file or a directory under `.test-build/`. It is run alone, as
//   named, and must exist; a directory must hold at least one `*.test.js`.
// - Options go to `node --test` before the files: after a file, `node --test` ignores them.
// - `--env NAME=VALUE` sets a variable for the run; a shell prefix (`NAME=1 npm …`) does not
//   work on Windows.
// - The arguments given to node are `nodeTestArguments`'s (tools/node-test-arguments.mjs).
// - Every file runs in a process of its own (`node --test`'s process isolation), one file at
//   a time, with no timeout: a file ends on its result.
// - Every file's process may mock a module (`--experimental-test-module-mocks`), as in
//   `@mcp-abap-adt/auth-providers`: one runner, the same flags.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, normalize, sep } from 'node:path';
import { nodeTestArguments } from './node-test-arguments.mjs';

const ROOT = '.test-build';
const env = { ...process.env };
const options = [];
const paths = [];

/** Whether `arg` names a path under `.test-build/` (or the directory itself). */
function underRoot(arg) {
  const path = normalize(arg);
  return path === ROOT || path.startsWith(`${ROOT}${sep}`);
}

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === '--env') {
    const pair = args[i + 1] ?? '';
    i += 1;
    const eq = pair.indexOf('=');
    if (eq < 1) {
      console.error(`run-tests: --env takes NAME=VALUE, got "${pair}"`);
      process.exit(2);
    }
    env[pair.slice(0, eq)] = pair.slice(eq + 1);
  } else if (arg.endsWith('.test.js') || underRoot(arg)) {
    paths.push(arg);
  } else {
    options.push(arg);
  }
}

function testFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...testFiles(path));
    else if (entry.name.endsWith('.test.js')) found.push(path);
  }
  return found;
}

const files = [];
if (paths.length === 0) {
  if (!existsSync(ROOT)) {
    console.error(
      `run-tests: ${ROOT}/ does not exist — run the test build first`,
    );
    process.exit(1);
  }
  paths.push(ROOT);
}
for (const path of paths) {
  if (!existsSync(path)) {
    console.error(`run-tests: ${path} does not exist`);
    process.exit(1);
  }
  if (!statSync(path).isDirectory()) {
    files.push(path);
    continue;
  }
  const found = testFiles(path).sort();
  if (found.length === 0) {
    console.error(
      `run-tests: no *.test.js under ${path}/ — the test build produced none`,
    );
    process.exit(1);
  }
  files.push(...found);
}
const run = spawnSync(process.execPath, nodeTestArguments({ options, files }), {
  stdio: 'inherit',
  env,
});
process.exit(run.status ?? 1);
