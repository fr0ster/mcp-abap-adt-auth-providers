/**
 * Opening the authorization URL runs no shell (Task 26 fix round 1).
 *
 * The URL may come from OIDC discovery or configuration. 5.4.2's fallback
 * handed it to `child_process.exec` inside double quotes, so `$(…)` or a
 * backtick in it ran as a command. Now every launcher is a program started
 * with an argument array, the URL one element of it, and only an http(s) URL
 * — as its serialisation — is launched.
 *
 * - each shipped browser's exact argv, System32 paths and no `cmd`:
 *   `shippedBrowsers.test.ts`.
 * - `runLauncher` for real, with a node script as the launcher: a hostile
 *   URL reaches it as one argument and no MARKER file is created.
 */

import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, jest } from '@jest/globals';

type SpawnCall = { command: string; args: string[]; options: unknown };
const spawned: SpawnCall[] = [];
const realChildProcess =
  jest.requireActual<typeof import('node:child_process')>('node:child_process');
const mode: { record: boolean } = { record: true };

jest.mock('node:child_process', () => ({
  ...jest.requireActual<Record<string, unknown>>('node:child_process'),
  spawn: (command: string, args: string[], options: unknown) => {
    if (!mode.record) {
      return realChildProcess.spawn(
        command,
        args,
        options as Parameters<typeof realChildProcess.spawn>[2],
      );
    }
    spawned.push({ command, args, options });
    // A fake child that exits 0 at once.
    const { EventEmitter } =
      jest.requireActual<typeof import('node:events')>('node:events');
    const child = new EventEmitter() as InstanceType<typeof EventEmitter> & {
      unref(): void;
    };
    child.unref = () => undefined;
    setImmediate(() => child.emit('exit', 0));
    return child;
  },
  exec: () => {
    throw new Error('exec must never be called');
  },
}));

import { launchableUrl, runLauncher } from '../../auth/browserLaunch';

/** `${IFS}` as text: a shell's word separator, no space for the URL to encode. */
const IFS = ['$', '{IFS}'].join('');
const HOSTILE =
  // No space in the commands: `${IFS}` survives the URL serialisation, so a
  // shell that saw this URL would really run them (the 1a mutation proves it).
  `https://idp.example/authorize?a=$(touch${IFS}MARKER1)&b=\`touch${IFS}MARKER2\`;touch${IFS}MARKER3&c="q'%26&d=%(PATH)`;
/**
 * For the real run: a URL a shell would parse cleanly (no stray quote or
 * parenthesis to stop it with a syntax error), so a shell would run all
 * three commands.
 */
const SHELL_HOSTILE = `https://idp.example/authorize?a=$(touch${IFS}MARKER1)&b=\`touch${IFS}MARKER2\`;touch${IFS}MARKER3`;
const CALLBACK = 'http://localhost:61001/callback';
const realPlatform = process.platform;

function onPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value: platform });
}

afterEach(() => {
  onPlatform(realPlatform);
  spawned.length = 0;
  mode.record = true;
});

describe('launchableUrl', () => {
  it.each([
    'javascript:alert(1)',
    'file:///etc/passwd',
    '--renderer-cmd-prefix=calc',
    'not a url',
    '',
  ])('refuses %j', (url) => {
    expect(launchableUrl(url)).toBeUndefined();
  });

  // Re-review: what the serialiser keeps but ShellExecute would split or
  // reinterpret is refused, and the host must be a host name or an address.
  it.each([
    'http://a"b/',
    'https://idp.example/a?x=1^2',
    'https://idp.example/a?x=1|2',
    'http://a%20b/',
    'http://exa!mple/',
  ])('refuses %j (left with a character ShellExecute would misread)', (url) => {
    expect(launchableUrl(url)).toBeUndefined();
  });

  it.each([
    ['https://IDP.Example:8443/a?b=c#d', 'https://idp.example:8443/a?b=c#d'],
    ['http://127.0.0.1:61001/cb', 'http://127.0.0.1:61001/cb'],
    ['http://[::1]:61001/cb', 'http://[::1]:61001/cb'],
    ['https://my_host.local/x', 'https://my_host.local/x'],
  ])('keeps %j', (url, href) => {
    expect(launchableUrl(url)).toBe(href);
  });

  it('serialises an http(s) URL: no space and no double quote survive', () => {
    const href = launchableUrl('https://idp.example/a b?x="y z"#"f"');
    expect(href).toBe('https://idp.example/a%20b?x=%22y%20z%22#%22f%22');
  });
});

describe('runLauncher, for real: a hostile URL runs nothing', () => {
  it('reaches the launcher as one argument; no MARKER is created', async () => {
    mode.record = false;
    const dir = mkdtempSync(join(tmpdir(), 'launch-'));
    const out = join(dir, 'argv.json');
    // The launcher: a script file (a plain path), recording its arguments.
    const recorder = join(dir, 'recorder.js');
    writeFileSync(
      recorder,
      'require("fs").writeFileSync(process.argv[2], JSON.stringify(process.argv.slice(3)))',
    );
    const href = launchableUrl(SHELL_HOSTILE) as string;
    const markers = () =>
      readdirSync(process.cwd()).filter((f) => f.startsWith('MARKER'));
    try {
      let failed: unknown;
      runLauncher(
        {
          command: process.execPath,
          args: [recorder, out, href],
          settlesOn: 'exit',
        },
        {
          onFailure: (error) => {
            failed = error ?? new Error('the launcher failed');
          },
        },
      );
      // Until the launcher wrote its argv, or it failed; then
      // let anything a shell would have started finish.
      await new Promise<void>((resolve) => {
        const poll = setInterval(() => {
          if (existsSync(out) || failed !== undefined) {
            clearInterval(poll);
            resolve();
          }
        }, 20);
      });
      await new Promise((resolve) => setTimeout(resolve, 300));
      // First: nothing ran (with a shell, `$(…)` and the backticks would
      // have created these).
      expect(markers()).toEqual([]);
      expect(failed).toBeUndefined();
      expect(JSON.parse(readFileSync(out, 'utf8'))).toEqual([href]);
      expect(readdirSync(dir).sort()).toEqual(['argv.json', 'recorder.js']);
    } finally {
      for (const marker of markers()) rmSync(marker, { force: true });
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('no shell in src', () => {
  it('no exec, execSync or shell option anywhere in src', () => {
    const { readdirSync: list, statSync } =
      jest.requireActual<typeof import('node:fs')>('node:fs');
    const src = join(__dirname, '..', '..');
    const files = (dir: string): string[] =>
      list(dir).flatMap((name) => {
        const path = join(dir, name);
        if (name === '__tests__') return [];
        if (statSync(path).isDirectory()) return files(path);
        return name.endsWith('.ts') ? [path] : [];
      });
    const hits = files(src).flatMap((file) =>
      readFileSync(file, 'utf8')
        .split('\n')
        .filter(
          (line) =>
            line.includes('child_process.exec') ||
            line.includes('execSync') ||
            line.includes('shell:') ||
            // `exec` imported by name (execFile with an argument array is
            // no shell, and RegExp's `.exec(` is not a process).
            (line.startsWith('import') && /[{,\s]exec[\s,}]/.test(line)),
        )
        .map((line) => `${file}: ${line.trim()}`),
    );
    expect(hits).toEqual([]);
  });
});
