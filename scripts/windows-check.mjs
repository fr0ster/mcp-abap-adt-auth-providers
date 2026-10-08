#!/usr/bin/env node
/**
 * windows-check.mjs — checks on a Windows host what the Linux test stand
 * cannot. Not shipped (not in package.json `files`); plain Node, no
 * dependency beyond the built package and, for check 4 only,
 * @mcp-abap-adt/sap-rfc-lite.
 *
 * 1. PREPARE, in order
 *
 *   1. A Windows host (x64 or arm64), Windows 10 1803 or later (check 3's
 *      wildcard cases use the system's own curl.exe and whoami.exe).
 *   2. Checks 1, 2 and 4: SAP GUI for Windows and the SAP Secure Login
 *      Client installed. Check 4 also: a Secure Login Client profile using
 *      Kerberos, logged on; SNC enabled for the target system's entry in SAP
 *      Logon (Properties → Network → "Activate Secure Network
 *      Communication"); a logon from SAP Logon without a password working.
 *      Check 3 needs nothing SAP; its chrome / msedge cases need that
 *      browser installed (otherwise that case is SKIPPED).
 *   3. Check 4 only: the SAP NW RFC SDK 7.50 for Windows x64 unpacked (e.g.
 *      C:\nwrfcsdk); SAPNWRFC_HOME set to that folder (the one holding lib\
 *      and include\); %SAPNWRFC_HOME%\lib on PATH. Open a NEW terminal after
 *      setting them.
 *   4. Node.js 22, 24 or 26, and git. Check 4 also: the C++ build tools
 *      node-gyp needs (Visual Studio Build Tools with "Desktop development
 *      with C++", and Python 3), since sap-rfc-lite is built on install.
 *   5. The package, built:
 *        git clone https://github.com/fr0ster/mcp-abap-adt-auth-providers
 *        cd mcp-abap-adt-auth-providers
 *        git checkout feat/error-contract
 *        npm ci
 *        npm run build
 *   6. Check 4 only:
 *        npm i --no-save @mcp-abap-adt/sap-rfc-lite
 *      Without it check 4 is SKIPPED; checks 1–3 still run.
 *   7. Check 4's inputs — environment variables, or answered at the prompts
 *      when they are missing (no password is ever asked for):
 *        SNC_CHECK_ASHOST    application server host     } one of the two
 *        SNC_CHECK_SYSNR     its system number (e.g. 00) }
 *        SNC_CHECK_MSHOST    message server host         } or a message
 *        SNC_CHECK_MSSERV    its port or service (opt.)  } server with
 *        SNC_CHECK_SYSID     the system id (e.g. DEV)    } SYSID and GROUP
 *        SNC_CHECK_GROUP     the logon group (e.g. PUBLIC)
 *        SNC_CHECK_SAPROUTER SAP router string (optional)
 *        SNC_CHECK_CLIENT    the client (e.g. 100)
 *        SNC_CHECK_PARTNER   the system's SNC name, as in SAP Logon
 *                            (e.g. p:CN=DEV, OU=..., or a Kerberos SPN p:SAPServiceDEV@REALM)
 *        SNC_CHECK_QOP       optional, default 9
 *        SNC_CHECK_LANG      optional, default EN
 *      The host, partner name and client are used, never printed.
 *
 * 2. RUN, from the repository root
 *
 *   node scripts/windows-check.mjs                  all checks
 *   node scripts/windows-check.mjs --only=1,3       only checks 1 and 3
 *   node scripts/windows-check.mjs --only=snc       by name: registry, abort, browser, snc
 *   node scripts/windows-check.mjs --browser-cases=default,brackets
 *                                                   which cases check 3 runs (default:
 *                                                   default,chrome,msedge,brackets,star,injection)
 *   node scripts/windows-check.mjs --no-prompt      never ask; missing input → SKIPPED
 *   node scripts/windows-check.mjs --show-reg-output
 *                                                   also print reg.exe's lines (paths only)
 *   node scripts/windows-check.mjs --help           this list
 *
 *   Check 3 opens browser tabs on a local page (127.0.0.1) and may flash
 *   console windows; close the tabs afterwards. Check 4 may show the Secure
 *   Login Client's logon window, and asks before its optional part 4c.
 *
 * 3. WHAT EACH CHECK DOES
 *
 *   1 registry  finds the SNC library through the real reg.exe
 *               (HKLM\Software\SAP\SecureLogin), SNC_LIB / SNC_LIB_64 ignored.
 *   2 abort     aborts while reg.exe runs — nodeSncSystem().readRegistryValue
 *               and SncLogonProvider.prepare() must answer interactive-login /
 *               aborted, and the reg.exe child must not be left running.
 *   3 browser   opens a local recorder page through the public browsers'
 *               open(url, signal); records whether the URL arrived unchanged,
 *               whether a command interpreter was a direct child of the
 *               launcher (process watch), and how open() settled:
 *     default     windowsDefaultBrowser() — rundll32 url.dll,FileProtocolHandler.
 *     chrome      windowsBrowser('chrome') — PowerShell Start-Process.
 *     msedge      windowsBrowser('msedge') — the same, Edge.
 *     brackets    windowsBrowser(%TEMP%\windows-check-XXXXXX\wc-[ab].exe), a copy of curl.exe
 *                 that requests the page, beside decoys wc-a.exe / wc-b.exe
 *                 (copies of whoami.exe) that [ab] matches as a wildcard. PASS:
 *                 the copy of curl requested the page, or open() rejected and no
 *                 decoy ran; FAIL: a decoy ran, or open() resolved and nothing
 *                 requested the page.
 *     star        windowsBrowser(%TEMP%\windows-check-XXXXXX\wc-[ab]*.exe): no file can have
 *                 that name, so the launch must fail; FAIL if a decoy (or
 *                 anything) started, or open() resolved.
 *     injection   windowsBrowser(a program string with " and ' quotes and ;
 *                 around an Invoke-WebRequest to the recorder): it must start
 *                 nothing and fail to launch; FAIL if the recorder sees the
 *                 injected request, anything started, or open() resolved.
 *   4 snc       a live SNC logon through the Secure Login Client:
 *     4a          prepare() Ok, the logon, RFC_PING and STFC_CONNECTION.
 *     4b          a wrong partner name must be refused (snc or system-refused).
 *     4c          optional: with the client exited, prepare() must be Ok; the
 *                 logon either succeeds (the library starts the client) or is
 *                 refused (snc or system-refused), never answered Ok.
 *
 * 4. SEND BACK
 *
 *   The SUMMARY block printed at the end (copy it whole). It carries the
 *   status of each check and short facts — library paths, process names,
 *   error kinds and fixed words — and no secret: no password is used, the
 *   host and SNC partner name are not printed, no temporary path is printed,
 *   and no exception's message is printed (failures go through auth-errors'
 *   readFailure / logFields).
 */

import { once } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import util from 'node:util';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const IS_WINDOWS = process.platform === 'win32';

// ── arguments ──────────────────────────────────────────────────────────────

const CHECKS = [
  { id: 1, name: 'registry', title: 'SNC library from the registry' },
  { id: 2, name: 'abort', title: 'reg.exe killed on abort' },
  {
    id: 3,
    name: 'browser',
    title: 'browser launch (windowsDefaultBrowser / windowsBrowser)',
  },
  { id: 4, name: 'snc', title: 'live SNC logon' },
];

const BROWSER_CASES = [
  'default',
  'chrome',
  'msedge',
  'brackets',
  'star',
  'injection',
];

function parseArgs(argv) {
  const options = {
    only: null,
    browserCases: [...BROWSER_CASES],
    prompt: true,
    showRegOutput: false,
    help: false,
  };
  for (const arg of argv) {
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--no-prompt') options.prompt = false;
    else if (arg === '--show-reg-output') options.showRegOutput = true;
    else if (arg.startsWith('--only=')) {
      options.only = new Set(
        arg
          .slice('--only='.length)
          .split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      );
    } else if (arg.startsWith('--browser-cases=')) {
      options.browserCases = arg
        .slice('--browser-cases='.length)
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const unknown = options.browserCases.filter(
        (c) => !BROWSER_CASES.includes(c),
      );
      if (unknown.length) {
        process.stderr.write(
          `unknown browser case(s): ${unknown.join(', ')} (one of ${BROWSER_CASES.join(', ')})\n`,
        );
        process.exit(2);
      }
    } else {
      process.stderr.write(`unknown argument: ${arg} (see --help)\n`);
      process.exit(2);
    }
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
  process.stdout.write(
    'node scripts/windows-check.mjs [--only=1,2,3,4|registry,abort,browser,snc]\n' +
      `  [--browser-cases=${BROWSER_CASES.join(',')}]\n` +
      '  [--no-prompt] [--show-reg-output] [--help]\n' +
      'What to prepare, what each check does and what to send back: see the\n' +
      'comment at the top of this file.\n',
  );
  process.exit(0);
}

// ── instrumentation, installed BEFORE the package is loaded ─────────────────
//
// The package's own code starts the children; the script only learns their
// PIDs. `SncSystem` promisifies `execFile` when it is loaded, so its custom
// promisified form is wrapped here first; the shipped browsers call `spawn`.

const childProcess = require('node:child_process');
const originalSpawn = childProcess.spawn;
const originalExecFile = childProcess.execFile;
const originalExecFileAsync = originalExecFile[util.promisify.custom];
/** Children the package started while recording: { via, command, child }. */
const recorded = [];
let recording = false;
/** Called with each recorded child, synchronously after it was started. */
let onRecorded = null;

function record(via, command, child) {
  if (!recording || !child) return;
  const entry = { via, command, child };
  recorded.push(entry);
  onRecorded?.(entry);
}

function execFileWrapper(...args) {
  return originalExecFile.apply(this, args);
}
execFileWrapper[util.promisify.custom] = (...args) => {
  const promise = originalExecFileAsync(...args);
  record('execFile', args[0], promise.child);
  return promise;
};
childProcess.execFile = execFileWrapper;
childProcess.spawn = function spawnWrapper(...args) {
  const child = originalSpawn.apply(this, args);
  record('spawn', args[0], child);
  return child;
};

// ── the package ────────────────────────────────────────────────────────────

let lib;
let sncSystemModule;
let errors;
try {
  lib = require(path.join(ROOT, 'dist', 'index.js'));
  sncSystemModule = require(path.join(ROOT, 'dist', 'snc', 'SncSystem.js'));
  errors = require('@mcp-abap-adt/auth-errors');
} catch {
  process.stderr.write(
    'The built package is missing: run `npm ci` and `npm run build` in the repository root first.\n',
  );
  process.exit(2);
}

// ── helpers ────────────────────────────────────────────────────────────────

const execFile = util.promisify(originalExecFile);
const SYSTEM32 = path.win32.join(
  process.env.SystemRoot?.trim() || 'C:\\Windows',
  'System32',
);
const REG_EXE = path.win32.join(SYSTEM32, 'reg.exe');
const TASKLIST_EXE = path.win32.join(SYSTEM32, 'tasklist.exe');
const POWERSHELL_EXE = path.win32.join(
  SYSTEM32,
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);
const SLC_KEY = 'HKLM\\Software\\SAP\\SecureLogin';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A thrown value as a line may show it: auth-errors' words, never its message. */
function safe(thrown, operation = 'unfamiliar-error') {
  // The script's own errors carry its own fixed words.
  if (thrown?.scriptOwn === true) return `script: ${thrown.message}`;
  try {
    const fields = errors.logFields(errors.readFailure(thrown, operation));
    return `${fields.kind}: ${fields.error}${
      fields.status === undefined ? '' : ` (status ${fields.status})`
    }`;
  } catch {
    return 'unknown error';
  }
}

/** A minted error (a refusal) as a line may show it, facts included. */
function describeError(error) {
  const fields = errors.logFields(error);
  const facts = error?.facts === undefined ? '' : JSON.stringify(error.facts);
  return [
    `kind=${fields.kind}`,
    `words="${fields.error}"`,
    ...(facts ? [`facts=${facts}`] : []),
    ...(fields.diagnostics
      ? [`diagnostics=${JSON.stringify(fields.diagnostics)}`]
      : []),
  ].join(' ');
}

/** Bounds a wait of the script itself (the package has no timer). */
function within(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(Object.assign(new Error(label), { scriptOwn: true })),
        ms,
      );
    }),
  ]).finally(() => clearTimeout(timer));
}

/** A one-line, printable form of a value the script chose to show. */
function shown(value) {
  return JSON.stringify(String(value));
}

class Result {
  constructor(check) {
    this.check = check;
    this.status = null;
    this.reason = '';
    this.details = [];
  }
  detail(line) {
    this.details.push(line);
    process.stdout.write(`      ${line}\n`);
  }
  pass() {
    this.status ??= 'PASS';
  }
  fail(line) {
    if (line) this.detail(`FAIL: ${line}`);
    this.status = 'FAIL';
  }
  skip(reason) {
    this.status ??= 'SKIPPED';
    this.reason = reason;
  }
}

let rl = null;
async function ask(question) {
  if (!options.prompt || !process.stdin.isTTY) return null;
  rl ??= createInterface({ input: process.stdin, output: process.stdout });
  return (await rl.question(`  ? ${question} `)).trim();
}

// ── check 1: the registry lookup ───────────────────────────────────────────

async function regQuery(args) {
  try {
    const { stdout } = await execFile(REG_EXE, args, { windowsHide: true });
    return { ok: true, stdout };
  } catch (error) {
    return {
      ok: false,
      stdout: typeof error?.stdout === 'string' ? error.stdout : '',
      exit: typeof error?.code === 'number' ? error.code : undefined,
      code: typeof error?.code === 'string' ? error.code : undefined,
    };
  }
}

async function checkRegistry(r) {
  if (!IS_WINDOWS) return r.skip('not Windows');
  const real = lib.nodeSncSystem();
  r.detail(
    `process: ${process.arch}; SNC_LIB ${process.env.SNC_LIB ? 'set' : 'unset'}, SNC_LIB_64 ${process.env.SNC_LIB_64 ? 'set' : 'unset'} in the real environment (both unset for this check)`,
  );

  // The raw output, read apart from the package, to diagnose a miss.
  const all = await regQuery(['query', SLC_KEY, '/reg:64']);
  const lines = all.stdout.split(/\r?\n/).filter((line) => line.trim() !== '');
  r.detail(
    `reg query ${SLC_KEY} /reg:64: ${all.ok ? 'exit 0' : `failed (${all.code ?? `exit ${all.exit}`})`}, ${lines.length} non-empty line(s)` +
      `, REG_ lines ${lines.filter((l) => l.includes('REG_')).length}` +
      `, undecodable characters ${all.stdout.includes('\uFFFD') ? 'yes' : 'no'}`,
  );
  for (const name of ['InstallPath64', 'InstallPath32']) {
    const value = sncSystemModule.parseRegQuery(all.stdout, name);
    r.detail(
      `parseRegQuery(${name}) on that output: ${value === undefined ? 'not found' : `found ${shown(value)}`}`,
    );
  }
  if (options.showRegOutput) {
    for (const line of lines) r.detail(`| ${shown(line)}`);
  }

  // The lookup itself, through the package: nodeSncSystem with the two
  // variables removed, so the registry is the only candidate.
  let registryRead = null;
  const system = {
    platform: real.platform,
    arch: real.arch,
    env: { ...process.env, SNC_LIB: undefined, SNC_LIB_64: undefined },
    readHead: (file, bytes) => real.readHead(file, bytes),
    readRegistryValue: async (key, name, signal) => {
      const value = await real.readRegistryValue(key, name, signal);
      registryRead = { name, found: value !== undefined };
      return value;
    },
  };
  try {
    const found = await new lib.DefaultSncLibraryLocator(system).locate();
    r.detail(
      `DefaultSncLibraryLocator: source=registry (${registryRead?.name}) path=${shown(found.path)} archs=${JSON.stringify(found.archs)}`,
    );
    if (registryRead?.found !== true) {
      return r.fail('the library was found, but not through the registry');
    }
    r.pass();
  } catch (error) {
    r.detail(
      `registry value ${registryRead ? `${registryRead.name} ${registryRead.found ? 'found' : 'not found'}` : 'not read'}`,
    );
    r.fail(
      errors.isAuthProviderFailure(error)
        ? describeError(errors.readFailure(error, 'resolving-snc-library'))
        : safe(error, 'resolving-snc-library'),
    );
  }
}

// ── check 2: reg.exe killed on abort ───────────────────────────────────────

/** The PIDs of running reg.exe processes (tasklist, CSV lines only). */
async function regPids() {
  const { stdout } = await execFile(
    TASKLIST_EXE,
    ['/FI', 'IMAGENAME eq reg.exe', '/FO', 'CSV', '/NH'],
    { windowsHide: true },
  );
  const pids = new Set();
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.startsWith('"')) continue; // "INFO: no tasks" is localised
    const pid = Number(line.split('","')[1]);
    if (Number.isInteger(pid)) pids.add(pid);
  }
  return pids;
}

function exitOf(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return once(child, 'exit').then(([code, signal]) => ({ code, signal }));
}

/** Runs `start(signal)`; aborts as soon as the package starts reg.exe. */
async function abortAtRegStart(start) {
  const controller = new AbortController();
  recorded.length = 0;
  recording = true;
  onRecorded = (entry) => {
    if (/reg\.exe$/i.test(String(entry.command))) controller.abort();
  };
  let settled;
  try {
    settled = await within(
      Promise.resolve(start(controller.signal)).then(
        (value) => ({ value }),
        (error) => ({ error }),
      ),
      30_000,
      'the moment did not settle',
    );
  } finally {
    recording = false;
    onRecorded = null;
  }
  const child = recorded.find((e) =>
    /reg\.exe$/i.test(String(e.command)),
  )?.child;
  return { settled, child, aborted: controller.signal.aborted };
}

async function reportKill(r, label, child, before) {
  if (!child) return r.fail(`${label}: no reg.exe child was started`);
  const exit = await within(exitOf(child), 10_000, 'no exit').catch(() => null);
  await sleep(300);
  const after = await regPids();
  const left = [...after].filter((pid) => !before.has(pid));
  r.detail(
    `${label}: child pid ${child.pid}, exit ${exit ? `code=${exit.code} signal=${exit.signal}` : 'not observed within 10 s'}; ` +
      `still running: ${after.has(child.pid) ? 'YES' : 'no'}; reg.exe not there before: ${left.length ? left.join(',') : 'none'}`,
  );
  if (after.has(child.pid))
    r.fail(`${label}: the reg.exe child is still running`);
}

async function checkAbort(r) {
  if (!IS_WINDOWS) return r.skip('not Windows');
  const before = await regPids();
  r.detail(`reg.exe running before: ${before.size}`);

  // 2a: the machine seam, as the locator calls it.
  const seam = await abortAtRegStart((signal) =>
    lib.nodeSncSystem().readRegistryValue(SLC_KEY, 'InstallPath64', signal),
  );
  if ('value' in seam.settled) {
    r.fail('readRegistryValue: resolved instead of answering aborted');
  } else {
    const error = errors.readFailure(
      seam.settled.error,
      'resolving-snc-library',
    );
    r.detail(`readRegistryValue rejected: ${describeError(error)}`);
    if (
      error.kind !== 'interactive-login' ||
      error.facts?.outcome !== 'aborted'
    ) {
      r.fail('readRegistryValue: expected interactive-login / aborted');
    }
  }
  await reportKill(r, 'readRegistryValue', seam.child, before);

  // 2b: the moment — SncLogonProvider.prepare() with the config's signal.
  const moment = await abortAtRegStart((signal) =>
    lib.SncLogonProvider.forSecureLoginClient({
      partnerName: 'p:CN=ABORT-CHECK',
      signal,
    }).prepare(),
  );
  if ('error' in moment.settled) {
    r.fail(`prepare() threw: ${safe(moment.settled.error, 'preparing')}`);
  } else if (moment.settled.value?.ok !== false) {
    r.fail(
      moment.aborted
        ? 'prepare() answered Ok after the abort'
        : 'prepare() answered Ok without starting reg.exe',
    );
  } else {
    const refusal = moment.settled.value.refusal;
    r.detail(`prepare() answered: ${describeError(refusal)}`);
    if (
      refusal.kind !== 'interactive-login' ||
      refusal.facts?.outcome !== 'aborted'
    ) {
      r.fail('prepare(): expected interactive-login / aborted');
    }
  }
  await reportKill(r, 'prepare()', moment.child, before);
  r.pass();
}

// ── check 3: the browser launch ────────────────────────────────────────────

const INTERPRETERS = new Set([
  'cmd.exe',
  'powershell.exe',
  'pwsh.exe',
  'wscript.exe',
  'cscript.exe',
  'mshta.exe',
]);

/** Whether `exe` is registered under App Paths (HKLM or HKCU). */
async function appPathRegistered(exe) {
  for (const hive of ['HKLM', 'HKCU']) {
    const result = await regQuery([
      'query',
      `${hive}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\${exe}`,
      '/ve',
    ]);
    if (result.ok) return true;
  }
  return false;
}

/**
 * Samples the process list every ~50 ms and reports each process that was
 * not there at the start: `{ pid, ppid, name }`. A process living shorter
 * than a sample may be missed — said in the result.
 */
async function startProcessWatch() {
  const script = [
    "$ErrorActionPreference = 'SilentlyContinue'",
    '$known = @{}',
    "Get-CimInstance Win32_Process | ForEach-Object { $known[[string]$_.ProcessId + '|' + $_.Name] = 1 }",
    "[Console]::Out.WriteLine('READY'); [Console]::Out.Flush()",
    '$end = (Get-Date).AddSeconds(120)',
    'while ((Get-Date) -lt $end) {',
    "  Get-CimInstance Win32_Process | ForEach-Object { $k = [string]$_.ProcessId + '|' + $_.Name; if (-not $known[$k]) { $known[$k] = 1; [Console]::Out.WriteLine(('{0},{1},{2}' -f $_.ProcessId, $_.ParentProcessId, $_.Name)); [Console]::Out.Flush() } }",
    '  Start-Sleep -Milliseconds 50',
    '}',
  ].join('\n');
  const watcher = originalSpawn(
    POWERSHELL_EXE,
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true },
  );
  const seen = [];
  let buffer = '';
  let ready;
  const isReady = new Promise((resolve) => {
    ready = resolve;
  });
  let started = true;
  watcher.on('error', () => {
    started = false;
    ready();
  });
  watcher.stdout.setEncoding('utf8');
  watcher.stdout.on('data', (chunk) => {
    buffer += chunk;
    let at = buffer.indexOf('\n');
    while (at !== -1) {
      const line = buffer.slice(0, at).trim();
      buffer = buffer.slice(at + 1);
      if (line === 'READY') ready();
      else {
        const [pid, ppid, ...name] = line.split(',');
        seen.push({
          pid: Number(pid),
          ppid: Number(ppid),
          name: name.join(','),
        });
      }
      at = buffer.indexOf('\n');
    }
  });
  await within(isReady, 30_000, 'the process watch did not start');
  if (!started) {
    throw Object.assign(new Error('the process watch could not be started'), {
      scriptOwn: true,
    });
  }
  return {
    seen,
    stop: () => {
      watcher.kill();
    },
  };
}

/** The processes started below `roots`, by name. */
function descendants(seen, roots) {
  const below = new Set(roots);
  const found = [];
  let grew = true;
  while (grew) {
    grew = false;
    for (const p of seen) {
      if (!below.has(p.pid) && below.has(p.ppid)) {
        below.add(p.pid);
        found.push(p);
        grew = true;
      }
    }
  }
  return found;
}

/** A local page that records every request's path and query. */
async function startRecorder() {
  const requests = [];
  const waiters = [];
  const server = http.createServer((req, res) => {
    if (req.url !== '/favicon.ico') {
      requests.push(req.url);
      for (const waiter of waiters.splice(0)) waiter();
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      Connection: 'close',
    });
    res.end(
      '<!doctype html><title>windows-check</title><p>Received. You may close this tab.</p>',
    );
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    port: server.address().port,
    requests,
    changed: () =>
      new Promise((resolve) => {
        waiters.push(resolve);
      }),
    close: async () => {
      server.closeAllConnections();
      server.close();
      await once(server, 'close').catch(() => undefined);
    },
  };
}

/**
 * The program check 3 hands a case, and what the case expects:
 * `url` — the browser (or the copy of curl) must request the page;
 * `nothing` — nothing may start and the launch must fail.
 */
async function browserCase(label, recorderPort) {
  switch (label) {
    case 'default':
      return { browser: lib.windowsDefaultBrowser(), expects: 'url' };
    case 'chrome':
    case 'msedge':
      if (!(await appPathRegistered(`${label}.exe`))) {
        return {
          skip: 'not registered under App Paths — not installed?',
        };
      }
      return { browser: lib.windowsBrowser(label), expects: 'url' };
    case 'brackets':
    case 'star': {
      const dir = wildcardDirectory();
      if (!dir) {
        return {
          skip: 'System32 curl.exe or whoami.exe missing, or the temporary directory could not be prepared',
        };
      }
      // `wc-[ab]` as a wildcard matches `wc-a` / `wc-b` (the decoys), never
      // the literal `wc-[ab]` (the intended copy of curl).
      const program =
        label === 'brackets'
          ? path.win32.join(dir, 'wc-[ab].exe')
          : path.win32.join(dir, 'wc-[ab]*.exe');
      return {
        browser: lib.windowsBrowser(program),
        expects: label === 'brackets' ? 'url' : 'nothing',
        decoys: ['wc-a.exe', 'wc-b.exe'],
      };
    }
    case 'injection': {
      // Quotes of both kinds and `;` around a command that would request
      // the recorder's /injected page if it ever reached PowerShell's parser.
      const injected = `http://127.0.0.1:${recorderPort}/injected`;
      const program = `wc-no-such-program" ; Invoke-WebRequest -UseBasicParsing -Uri '${injected}' ; "' ; Invoke-WebRequest -UseBasicParsing -Uri "${injected}" ; '`;
      return {
        browser: lib.windowsBrowser(program),
        expects: 'nothing',
        injectedPath: '/injected',
      };
    }
    default:
      return { skip: 'unknown case' };
  }
}

/** The temporary directory of the wildcard cases, made once; null when it cannot be. */
let wildcard;
function wildcardDirectory() {
  if (wildcard !== undefined) return wildcard?.dir ?? null;
  wildcard = null;
  const curl = path.win32.join(SYSTEM32, 'curl.exe');
  const whoami = path.win32.join(SYSTEM32, 'whoami.exe');
  try {
    if (!fs.existsSync(curl) || !fs.existsSync(whoami)) return null;
    // The brackets are in the file names only: a directory named with them
    // would, read as a wildcard, match no directory at all, and the decoys
    // beside the intended program could never be reached.
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-check-'));
    const dir = root;
    fs.copyFileSync(curl, path.join(dir, 'wc-[ab].exe'));
    fs.copyFileSync(whoami, path.join(dir, 'wc-a.exe'));
    fs.copyFileSync(whoami, path.join(dir, 'wc-b.exe'));
    wildcard = { root, dir };
    return dir;
  } catch {
    return null;
  }
}

/** Removes the wildcard cases' directory; whether it is gone. */
async function removeWildcardDirectory() {
  if (!wildcard) return null;
  for (let i = 0; i < 10; i += 1) {
    try {
      fs.rmSync(wildcard.root, { recursive: true, force: true });
      if (!fs.existsSync(wildcard.root)) return true;
    } catch {}
    await sleep(500); // a copy may still be running
  }
  return false;
}

/** How `open()` settled, in fixed words only. */
function settlement(settled, ms) {
  if (settled === null) return 'not settled';
  if ('value' in settled) return `resolved after ${ms} ms`;
  return `rejected after ${ms} ms — ${describeError(errors.readFailure(settled.error, 'opening-browser'))}`;
}

async function launchOnce(r, label) {
  const recorder = await startRecorder();
  let watch = null;
  const controller = new AbortController();
  try {
    const chosen = await browserCase(label, recorder.port);
    if (chosen.skip) {
      r.detail(`${label}: SKIPPED (${chosen.skip})`);
      return false;
    }
    const pathname = `/launch-${label}`;
    const expected = `${pathname}?a=1&b=two%20words`;
    const url = `http://127.0.0.1:${recorder.port}${expected}#frag`;
    watch = await startProcessWatch();

    // open(url, signal), as a composition calls it; the launcher's PID is
    // learnt through the spawn wrapper while open() runs.
    recorded.length = 0;
    recording = true;
    const started = Date.now();
    let settled = null;
    let settledAt = 0;
    let opened;
    try {
      opened = Promise.resolve(chosen.browser.open(url, controller.signal));
    } catch (error) {
      opened = Promise.reject(error);
    }
    const watched = opened.then(
      (value) => {
        settled = { value };
        settledAt = Date.now();
      },
      (error) => {
        settled = { error };
        settledAt = Date.now();
      },
    );

    // The TEST's own bound for the request and the settlement: 60 s.
    const deadline = Date.now() + 60_000;
    const arrived = () =>
      recorder.requests.some((u) => u.startsWith(pathname)) ||
      (chosen.injectedPath !== undefined &&
        recorder.requests.some((u) => u.startsWith(chosen.injectedPath)));
    while (
      Date.now() < deadline &&
      !(settled !== null && (arrived() || 'error' in settled)) &&
      !(settled !== null && chosen.expects === 'nothing')
    ) {
      await Promise.race([
        recorder.changed(),
        watched,
        sleep(Math.max(0, Math.min(1_000, deadline - Date.now()))),
      ]);
    }
    let abortedByScript = false;
    if (settled === null) {
      abortedByScript = true;
      controller.abort();
      await within(
        watched,
        10_000,
        'open() did not settle after the abort',
      ).catch(() => undefined);
    }
    recording = false;
    await sleep(2_000); // let the launcher's children (and a late request) show up
    watch.stop();

    const roots = recorded.map((e) => e.child.pid).filter(Number.isInteger);
    r.detail(
      `${label}: launcher ${recorded.map((e) => shown(path.win32.basename(String(e.command)))).join(', ') || 'none started'} (pid ${roots.join(',') || '-'})`,
    );
    r.detail(
      `${label}: open() ${abortedByScript ? 'did not settle within 60 s; the script aborted its signal, then it ' : ''}${settlement(settled, settledAt - started)}`,
    );

    const below = descendants(watch.seen, roots);
    const names = [...new Set(below.map((p) => p.name.toLowerCase()))];
    // Only the launcher's own children count: a browser starts interpreters
    // of its own further down (native-messaging hosts of extensions run as
    // `cmd /c`), which says nothing about how the launcher reached it.
    const direct = [
      ...new Set(
        watch.seen
          .filter((p) => roots.includes(p.ppid))
          .map((p) => p.name.toLowerCase()),
      ),
    ];
    const interpreters = direct.filter((n) => INTERPRETERS.has(n));
    const deeper = names.filter(
      (n) => INTERPRETERS.has(n) && !direct.includes(n),
    );
    r.detail(
      `${label}: processes started below the launcher: ${names.length ? names.join(', ') : 'none seen'} (sampled every ~50 ms); direct children: ${direct.length ? direct.join(', ') : 'none seen'}` +
        (deeper.length
          ? `; interpreters deeper down (the browser's own, not counted): ${deeper.join(', ')}`
          : ''),
    );
    if (interpreters.length) {
      r.fail(
        `${label}: a command interpreter ran as a direct child of the launcher: ${interpreters.join(', ')}`,
      );
    }

    const received = recorder.requests.filter((u) => u.startsWith(pathname));
    if (received.length) {
      r.detail(`${label}: received ${received.map(shown).join(', ')}`);
    }
    const resolved = settled !== null && 'value' in settled;
    const decoys = (chosen.decoys ?? []).filter((d) =>
      watch.seen.some((p) => p.name.toLowerCase() === d),
    );
    if (decoys.length) {
      r.fail(
        `${label}: a different program started (a wildcard match): ${decoys.join(', ')}`,
      );
    }

    if (chosen.expects === 'url') {
      if (received.length) {
        if (!received.includes(expected)) {
          r.fail(`${label}: expected exactly ${shown(expected)}`);
        }
        if (!resolved) {
          r.detail(
            `${label}: the page was requested, but open() did not resolve`,
          );
          if (label !== 'brackets') r.fail(`${label}: open() did not resolve`);
        }
      } else if (label === 'brackets' && !resolved && !decoys.length) {
        r.detail(
          `${label}: a clear launch failure — the intended program did not start, and neither did a decoy`,
        );
      } else if (settled !== null && 'error' in settled) {
        r.fail(`${label}: the launch failed (open() rejected)`);
      } else {
        r.fail(`${label}: no request reached the page within 60 s`);
      }
    } else {
      const injected =
        chosen.injectedPath === undefined
          ? []
          : recorder.requests.filter((u) => u.startsWith(chosen.injectedPath));
      if (injected.length) {
        r.fail(
          `${label}: the program string altered the command — the injected request arrived`,
        );
      }
      if (received.length) {
        r.fail(`${label}: something requested the page`);
      }
      // conhost.exe hosts the launcher's own console; it is not a program
      // the launcher started.
      const startedHere = direct.filter((n) => n !== 'conhost.exe');
      if (startedHere.length) {
        r.fail(
          `${label}: the launcher started ${startedHere.join(', ')} for a program that cannot exist`,
        );
      }
      if (resolved) {
        r.fail(`${label}: open() resolved — expected a launch failure`);
      } else if (!injected.length && !received.length && !startedHere.length) {
        r.detail(`${label}: a clear launch failure, nothing started`);
      }
    }
    return true;
  } finally {
    recording = false;
    controller.abort();
    watch?.stop();
    await recorder.close();
  }
}

async function checkBrowser(r) {
  if (!IS_WINDOWS) return r.skip('not Windows');
  let ran = 0;
  try {
    for (const label of options.browserCases) {
      try {
        if (await launchOnce(r, label)) ran += 1;
      } catch (error) {
        r.fail(`${label}: ${safe(error)}`);
      }
    }
  } finally {
    const removed = await removeWildcardDirectory();
    if (removed !== null) {
      r.detail(
        `wildcard cases' temporary directory removed: ${removed ? 'yes' : 'NO — remove windows-check-* under %TEMP% by hand'}`,
      );
    }
  }
  if (ran === 0 && r.status === null) return r.skip('no browser case ran');
  r.detail('Close the browser tabs this check opened.');
  r.pass();
}

// ── check 4: the live SNC logon ────────────────────────────────────────────

async function sncInputs() {
  const env = process.env;
  const read = async (variable, question) =>
    env[variable]?.trim() || (await ask(question)) || '';
  const connection = {};
  const ashost = await read(
    'SNC_CHECK_ASHOST',
    'Application server host (empty to use a message server):',
  );
  if (ashost) {
    connection.ashost = ashost;
    connection.sysnr = await read(
      'SNC_CHECK_SYSNR',
      'System number (e.g. 00):',
    );
    if (!connection.sysnr) return null;
  } else {
    connection.mshost = await read('SNC_CHECK_MSHOST', 'Message server host:');
    if (!connection.mshost) return null;
    const msserv = await read(
      'SNC_CHECK_MSSERV',
      'Message server port or service (empty for the default):',
    );
    if (msserv) connection.msserv = msserv;
    connection.sysid = await read('SNC_CHECK_SYSID', 'System id (e.g. DEV):');
    connection.group = await read(
      'SNC_CHECK_GROUP',
      'Logon group (e.g. PUBLIC):',
    );
    if (!connection.sysid || !connection.group) return null;
  }
  const saprouter = env.SNC_CHECK_SAPROUTER?.trim();
  if (saprouter) connection.saprouter = saprouter;
  connection.client = await read('SNC_CHECK_CLIENT', 'Client (e.g. 100):');
  connection.lang = env.SNC_CHECK_LANG?.trim() || 'EN';
  const partnerName = await read(
    'SNC_CHECK_PARTNER',
    'SNC partner name of the system (as in SAP Logon):',
  );
  if (!connection.client || !partnerName) return null;
  return { connection, partnerName, qop: env.SNC_CHECK_QOP?.trim() || '9' };
}

/** prepare() and establish() of a provider; the logon parameters, or a refusal. */
async function parametersOf(r, label, provider) {
  const prepared = await provider.prepare();
  if (!prepared.ok) {
    r.detail(`${label}: prepare() refused: ${describeError(prepared.refusal)}`);
    return null;
  }
  let params = null;
  const established = await provider.establish({
    tlsMaterial: () => ({ ok: true }),
    logonParameters: (given) => {
      params = { ...given };
      return { ok: true };
    },
  });
  if (!established.ok || !params) {
    r.detail(
      `${label}: establish() refused: ${describeError(established.refusal)}`,
    );
    return null;
  }
  return params;
}

/** Opens an RFC connection with the parameters; the error, if it fails. */
async function logon(Client, connection, params) {
  const client = new Client({ ...connection, ...params });
  try {
    await client.open();
  } catch (error) {
    return { error };
  }
  try {
    await client.call('RFC_PING');
    const echo = await client.call('STFC_CONNECTION', {
      REQUTEXT: 'windows-check',
    });
    return { ok: true, echoed: echo?.ECHOTEXT === 'windows-check' };
  } catch (error) {
    return { error, afterOpen: true };
  } finally {
    await client.close().catch(() => undefined);
  }
}

/** The RFC error's allowlisted key only; never its message. */
function rfcKeyOf(error) {
  let key;
  try {
    key = error?.key;
  } catch {
    key = undefined;
  }
  return errors.isRfcKey(key) ? key : 'not on the allowlist';
}

async function checkSnc(r) {
  if (!IS_WINDOWS) return r.skip('not Windows');
  try {
    require.resolve('@mcp-abap-adt/sap-rfc-lite');
  } catch {
    return r.skip(
      '@mcp-abap-adt/sap-rfc-lite not installed (npm i --no-save @mcp-abap-adt/sap-rfc-lite)',
    );
  }
  let Client;
  try {
    ({ Client } = require('@mcp-abap-adt/sap-rfc-lite'));
  } catch (error) {
    return r.fail(
      `sap-rfc-lite did not load (${safe(error)}) — is %SAPNWRFC_HOME%\\lib on PATH?`,
    );
  }
  const inputs = await sncInputs();
  if (!inputs) return r.skip('inputs not given (see the header: SNC_CHECK_*)');
  const { connection, partnerName, qop } = inputs;
  r.detail(
    `target: ${connection.ashost ? 'application server' : 'message server'}${connection.saprouter ? ' via SAP router' : ''} (host, client and partner name not printed)`,
  );

  // 4a: the logon.
  const resolved = [];
  const logger = {
    debug: (message, fields) => {
      if (message === 'SNC library resolved') resolved.push(fields);
    },
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
  };
  const provider = lib.SncLogonProvider.forSecureLoginClient({
    partnerName,
    qop,
    logger,
  });
  const params = await parametersOf(r, '4a', provider);
  if (!params) return r.fail('4a: no logon parameters');
  const library = resolved[0];
  r.detail(
    `4a: prepare() Ok — library ${shown(library?.library)} archs=${JSON.stringify(library?.archs)} product=${shown(library?.product)}; parameters ${Object.keys(params).sort().join(', ')}`,
  );
  const first = await logon(Client, connection, params);
  if (first.ok) {
    r.detail(
      `4a: logon PASS — RFC_PING ok, STFC_CONNECTION echoed: ${first.echoed}`,
    );
    if (!first.echoed) r.fail('4a: STFC_CONNECTION did not echo the text');
  } else {
    const answer = await provider.rejected({ at: 'logon', error: first.error });
    r.fail(
      `4a: ${first.afterOpen ? 'a call after the logon' : 'the logon'} failed — RFC key ${rfcKeyOf(first.error)}; rejected(): ${answer.ok ? 'Ok' : describeError(answer.refusal)}`,
    );
  }

  // 4b: a wrong partner name must be refused. The SDK may answer with a GSS
  // code the provider explains (`snc`) or without one (the neutral
  // `system-refused` of rule 5); either is right, an Ok or a blamed
  // credential is not.
  const wrong = lib.SncLogonProvider.forSecureLoginClient({
    partnerName: 'p:CN=WINDOWS-CHECK-WRONG-PARTNER, O=INVALID',
    qop,
  });
  const wrongParams = await parametersOf(r, '4b', wrong);
  if (!wrongParams) {
    r.fail('4b: no logon parameters');
  } else {
    const second = await logon(Client, connection, wrongParams);
    if (second.ok) {
      r.fail('4b: the logon with a wrong partner name succeeded');
    } else {
      const answer = await wrong.rejected({ at: 'logon', error: second.error });
      r.detail(
        `4b: wrong partner refused — RFC key ${rfcKeyOf(second.error)}; rejected(): ${answer.ok ? 'Ok' : describeError(answer.refusal)}`,
      );
      if (
        answer.ok ||
        (answer.refusal.kind !== 'snc' &&
          answer.refusal.kind !== 'system-refused')
      ) {
        r.fail('4b: expected an snc or a system-refused refusal');
      }
    }
  }

  // 4c (optional): the Secure Login Client logged out / exited.
  const go = await ask(
    'Optional 4c: log out of (or exit) the Secure Login Client now, then press Enter. ' +
      "If its logon window appears, CLOSE it (cancel). Type 'skip' to skip:",
  );
  if (go === null || go.toLowerCase() === 'skip') {
    r.detail(
      `4c: SKIPPED (${go === null ? 'no prompt' : 'skipped by the user'})`,
    );
  } else {
    const stopped = lib.SncLogonProvider.forSecureLoginClient({
      partnerName,
      qop,
    });
    const stoppedParams = await parametersOf(r, '4c', stopped);
    if (!stoppedParams) {
      r.fail('4c: prepare() refused with the client stopped (documented: Ok)');
    } else {
      r.detail('4c: prepare() Ok with the client stopped, as documented');
      const third = await logon(Client, connection, stoppedParams);
      if (third.ok) {
        r.detail(
          '4c: SKIPPED — the logon succeeded: the library started the client, which logged on by itself (documented); the refusal needs its logon window closed',
        );
      } else {
        const answer = await stopped.rejected({
          at: 'logon',
          error: third.error,
        });
        r.detail(
          `4c: refused — RFC key ${rfcKeyOf(third.error)}; rejected(): ${answer.ok ? 'Ok' : describeError(answer.refusal)}`,
        );
        // With no credential the SDK may answer without a GSS code (a
        // neutral refusal) or with A2200019 (an snc one); either is right,
        // an Ok is not.
        if (
          answer.ok ||
          (answer.refusal.kind !== 'snc' &&
            answer.refusal.kind !== 'system-refused')
        ) {
          r.fail('4c: expected an snc or a system-refused refusal');
        }
      }
    }
  }
  r.pass();
}

// ── runner ─────────────────────────────────────────────────────────────────

const RUNNERS = {
  registry: checkRegistry,
  abort: checkAbort,
  browser: checkBrowser,
  snc: checkSnc,
};

const unhandled = [];
process.on('unhandledRejection', (reason) => {
  unhandled.push(safe(reason));
});

function selected(check) {
  return (
    options.only === null ||
    options.only.has(String(check.id)) ||
    options.only.has(check.name)
  );
}

async function main() {
  let version = 'unknown';
  try {
    version = require(path.join(ROOT, 'package.json')).version;
  } catch {}
  let commit = 'unknown';
  try {
    commit = (
      await execFile('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT })
    ).stdout.trim();
  } catch {}
  const header = `auth-providers ${version} (${commit}); node ${process.version}; ${process.platform} ${os.release()} ${process.arch}`;
  process.stdout.write(`windows-check — ${header}\n\n`);

  const results = [];
  for (const check of CHECKS) {
    const r = new Result(check);
    results.push(r);
    if (!selected(check)) {
      r.skip('not selected');
      continue;
    }
    process.stdout.write(`[${check.id}] ${check.title}\n`);
    try {
      await RUNNERS[check.name](r);
    } catch (error) {
      r.fail(`the check itself failed: ${safe(error)}`);
    }
    r.pass();
    process.stdout.write(
      `    → ${r.status}${r.status === 'SKIPPED' ? ` (${r.reason})` : ''}\n\n`,
    );
  }
  rl?.close();

  const lines = ['===== SUMMARY (send this back) =====', header];
  for (const r of results) {
    lines.push(
      `${r.check.id} ${r.check.name}: ${r.status}${r.status === 'SKIPPED' ? `(${r.reason})` : ''}`,
    );
    for (const d of r.details) lines.push(`    ${d}`);
  }
  if (unhandled.length)
    lines.push(`unhandled rejections: ${unhandled.join('; ')}`);
  lines.push('===== END SUMMARY =====');
  process.stdout.write(`${lines.join('\n')}\n`);
  process.exitCode = results.some((r) => r.status === 'FAIL') ? 1 : 0;
}

await main();
