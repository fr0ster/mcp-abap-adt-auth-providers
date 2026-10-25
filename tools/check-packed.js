// What a consumer installs from npm, not what the repository holds.
// Packs every package, checks each tarball (built output shipped, published
// ranges only, no install script, no native code), installs the tarballs into
// a fresh project outside the repository and loads each package there. Also
// checks every package-lock.json for links and non-registry sources.
//   npm run build && node tools/check-packed.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const { publishOrder } = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'),
);

const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
const problems = [];
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];

let work;
let files = [];
const names = [];

try {
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-providers-packed-'));
  const tarballs = path.join(work, 'tarballs');
  fs.mkdirSync(tarballs);

  for (const dir of publishOrder) {
    const pkgDir = path.join(ROOT, dir);

    // The lockfile is the development install: from the registry, no links.
    const lock = JSON.parse(
      fs.readFileSync(path.join(pkgDir, 'package-lock.json'), 'utf8'),
    );
    for (const [key, entry] of Object.entries(lock.packages ?? {})) {
      if (key === '') continue;
      if (entry.link === true)
        problems.push(`${dir}: package-lock.json has "link": true at ${key}`);
      else if (
        typeof entry.resolved === 'string' &&
        !entry.resolved.startsWith('https://registry.npmjs.org/')
      )
        problems.push(
          `${dir}: package-lock.json ${key} does not resolve from the registry`,
        );
    }

    run(
      'npm',
      ['pack', '--pack-destination', tarballs, '--silent'],
      pkgDir,
    );
  }
  files = fs.readdirSync(tarballs).map((f) => path.join(tarballs, f));

  for (const tgz of files) {
    const base = path.basename(tgz);
    const listing = run('tar', ['-tzf', tgz], work);
    for (const needed of ['package/dist/index.js', 'package/dist/index.d.ts'])
      if (!listing.includes(needed)) problems.push(`${base}: no ${needed}`);
    if (listing.split('\n').some((l) => /\.(node|gyp)$/.test(l)))
      problems.push(`${base}: ships native code`);
    const manifest = JSON.parse(
      run('tar', ['-xzOf', tgz, 'package/package.json'], work),
    );
    names.push(manifest.name);
    for (const field of [
      'dependencies',
      'optionalDependencies',
      'peerDependencies',
    ])
      for (const [dep, range] of Object.entries(manifest[field] ?? {}))
        if (/^(workspace:|file:|link:|\.|\/|git|http)/.test(range))
          problems.push(
            `${manifest.name}: ${dep} is "${range}", not a published range`,
          );
    for (const hook of INSTALL_SCRIPTS)
      if (manifest.scripts?.[hook] !== undefined)
        problems.push(`${manifest.name}: has a ${hook} script`);
  }

  if (!problems.length) {
    const consumer = path.join(work, 'consumer');
    fs.mkdirSync(consumer);
    fs.writeFileSync(
      path.join(consumer, 'package.json'),
      '{ "name": "consumer", "private": true }\n',
    );
    run(
      'npm',
      ['install', '--no-audit', '--no-fund', '--ignore-scripts', ...files],
      consumer,
    );
    fs.writeFileSync(
      path.join(consumer, 'runtime.js'),
      `const out = [];
for (const name of ${JSON.stringify(names)}) {
  try { require(name); } catch (e) { out.push(name + ': ' + e.code); }
}
console.log(JSON.stringify(out));
`,
    );
    problems.push(...JSON.parse(run('node', ['runtime.js'], consumer)));
  }
} catch (error) {
  problems.push(String(error?.message ?? error));
} finally {
  if (work) fs.rmSync(work, { recursive: true, force: true });
}

if (problems.length) {
  console.error(problems.join('\n'));
  console.error(`${problems.length} problem(s)`);
  process.exit(1);
}
console.log(
  `packed: ${files.length} tarball(s) install cleanly from the registry and load on their own`,
);
