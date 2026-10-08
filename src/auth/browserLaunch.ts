/**
 * Opening the authorization URL — the `open` package when it loads, else a
 * launcher of our own — no shell, ever. Every shipped `IBrowser`
 * (`systemBrowser()`, `chromeBrowser()`, `edgeBrowser()`,
 * `firefoxBrowser()`) launches through `launchBrowser`.
 *
 * The URL is not this package's to trust: an OIDC provider's
 * `authorization_endpoint` comes from its discovery document, and a
 * pre-built `authorizationUrl` from configuration. Handed to a shell inside
 * quotes, a `$(…)` or a backtick in it ran as a command (5.4.2 and before).
 * So:
 *
 * - the URL is parsed first and only an `http:` / `https:` URL is launched,
 *   as its WHATWG serialisation (`href`) — spaces and quotes percent-encoded,
 *   so it is one argument to whatever receives it and can never begin with
 *   `-` (no browser flag smuggled in);
 * - every launcher is a program started with an argument array
 *   (`child_process.spawn`, no `shell` option): the URL is one element of
 *   argv, which no shell parses;
 * - on Windows the launchers are the system's own, by absolute path under
 *   `%SystemRoot%\System32` (a bare name is searched in the current
 *   directory first), and the URL must hold no quote, space, `<`, `>`, `^`,
 *   `|`, backslash or control character and a valid host — reasoned from
 *   ShellExecute's parsing, not measured on a Windows host;
 * - on Windows `cmd /c start` is never used, since `cmd` parses `&`, `|`,
 *   `^` and `%` in its command line whatever the quoting. The default browser
 *   is opened by `rundll32 url.dll,FileProtocolHandler <url>`, which hands the
 *   rest of its command line to `ShellExecute` as the URL and runs no command
 *   interpreter. A named browser needs `ShellExecute`'s App Paths lookup
 *   (`chrome` is not on `PATH`), so it is started by PowerShell's
 *   `Start-Process` with a fixed command; the URL reaches it through an
 *   environment variable, never through PowerShell's parser.
 *
 * Candidates run in order, the next one when a launcher cannot be started or
 * exits non-zero — the `a || b || c` the shell fallback used to spell.
 */

import * as child_process from 'node:child_process';
import { win32 } from 'node:path';
import { AuthProviderFailure, classify } from '@mcp-abap-adt/auth-errors';
import { abortedFailure, throwIfAborted, untilAborted } from './attempt';
import { readSafely } from './knownCodes';

/** One way to start a browser: a program and its arguments. */
export interface LaunchCommand {
  readonly command: string;
  readonly args: readonly string[];
  /**
   * When the browser counts as asked: `'exit'` for a hand-off launcher that
   * exits by design once it passed the URL on (`xdg-open`, `open`,
   * `rundll32`, PowerShell's `Start-Process`) — a non-zero exit is a failure;
   * `'spawn'` for a browser binary started directly, which runs until the
   * user closes it — its start is the answer, its exit never awaited.
   */
  readonly settlesOn: 'exit' | 'spawn';
  /** Extra environment for the launcher (Windows' named browsers). */
  readonly env?: Readonly<Record<string, string>>;
}

/** The variable PowerShell reads the URL from (Windows, a named browser). */
export const URL_VARIABLE = 'MCP_ABAP_ADT_AUTHORIZATION_URL';

/** The browsers shipped as an `IBrowser` beside the system's default. */
export type NamedBrowser = 'chrome' | 'msedge' | 'firefox';

const MAC_APP: Readonly<Record<NamedBrowser, string>> = {
  chrome: 'Google Chrome',
  msedge: 'Microsoft Edge',
  firefox: 'Firefox',
};

const LINUX_EXECUTABLES: Readonly<Record<NamedBrowser, readonly string[]>> = {
  chrome: ['google-chrome', 'chromium', 'chromium-browser'],
  msedge: ['microsoft-edge', 'microsoft-edge-stable'],
  firefox: ['firefox', 'firefox-esr'],
};

/**
 * The URL to launch: an `http:` or `https:` URL as its serialisation, else
 * `undefined` (nothing is launched). Total.
 */
export function launchableUrl(url: unknown): string | undefined {
  if (typeof url !== 'string') return undefined;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return undefined;
  }
  const href = parsed.href;
  // ShellExecute (Windows) receives the URL as a string it splits and
  // matches by scheme: a quote, a space or a shell-ish character left in the
  // serialisation (the parser keeps `"` in a host, `^` and `|` in a query)
  // would make it something else. Refused, not repaired.
  for (const character of href) {
    const code = character.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f || UNSAFE.has(character)) {
      return undefined;
    }
  }
  return validHost(parsed.hostname) ? href : undefined;
}

/** Characters never launched, even where the URL serialiser keeps them. */
const UNSAFE: ReadonlySet<string> = new Set(['"', '<', '>', '^', '|', '\\']);

/**
 * A host name (letters, digits, `-`, `_`, in non-empty dot-separated labels,
 * as the parser lower-cases and punycodes it), an IPv4 address (the same
 * rule covers it) or a bracketed IPv6 address. Plain code: the URL is
 * already parsed.
 */
function validHost(hostname: string): boolean {
  if (hostname.startsWith('[')) {
    if (!hostname.endsWith(']') || hostname.length < 4) return false;
    for (const character of hostname.slice(1, -1)) {
      const hex =
        (character >= '0' && character <= '9') ||
        (character >= 'a' && character <= 'f');
      if (!hex && character !== ':' && character !== '.') return false;
    }
    return true;
  }
  if (hostname === '') return false;
  for (const label of hostname.split('.')) {
    if (label === '') return false;
    for (const character of label) {
      const allowed =
        (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character === '-' ||
        character === '_';
      if (!allowed) return false;
    }
  }
  return true;
}

/**
 * A program of the system's own `System32`, by absolute path: a bare name is
 * searched in the current directory before `PATH` on Windows, where a planted
 * `rundll32.exe` would receive the URL (as `reg.exe` in `SncSystem.ts`).
 */
function system32(...parts: string[]): string {
  return win32.join(
    process.env.SystemRoot?.trim() || 'C:\\Windows',
    'System32',
    ...parts,
  );
}

/** The launchers to try, in order, for `href` (already `launchableUrl`). */
export function launchCommands(
  platform: NodeJS.Platform,
  browser: NamedBrowser | undefined,
  href: string,
): LaunchCommand[] {
  if (platform === 'win32') {
    if (browser === undefined) {
      return [
        {
          command: system32('rundll32.exe'),
          args: ['url.dll,FileProtocolHandler', href],
          settlesOn: 'exit',
        },
      ];
    }
    return [
      {
        command: system32('WindowsPowerShell', 'v1.0', 'powershell.exe'),
        args: [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          // Fixed text: the URL is read from the environment at run time.
          `Start-Process -FilePath '${browser}' -ArgumentList $env:${URL_VARIABLE}`,
        ],
        env: { [URL_VARIABLE]: href },
        settlesOn: 'exit',
      },
    ];
  }
  if (platform === 'darwin') {
    return browser === undefined
      ? [{ command: 'open', args: [href], settlesOn: 'exit' }]
      : [
          {
            command: 'open',
            args: ['-a', MAC_APP[browser], href],
            settlesOn: 'exit',
          },
        ];
  }
  return browser === undefined
    ? [{ command: 'xdg-open', args: [href], settlesOn: 'exit' }]
    : LINUX_EXECUTABLES[browser].map((command) => ({
        command,
        args: [href],
        settlesOn: 'spawn' as const,
      }));
}

/** How `runLaunchers` reports, and when it stops trying. */
export interface LaunchCallbacks {
  /** Called once, with the last launcher's error (`undefined` for a non-zero exit), when none runs. */
  readonly onFailure: (error: unknown) => void;
  /** Called once when a launcher answered: exited `0`, or started (`settlesOn: 'spawn'`). */
  readonly onSuccess?: (() => void) | undefined;
  /** Checked before each launcher: `true` starts no further one. */
  readonly stopped?: (() => boolean) | undefined;
}

/**
 * Starts the first launcher that runs, without a shell. `onFailure` is
 * called once, with the last launcher's error (or `undefined` for a non-zero
 * exit), when none does — or when `stopped()` says to start no further one;
 * `onSuccess` once when one answers: a hand-off launcher by exiting `0`, a
 * browser binary by starting (its exit is never awaited). Never throws; the
 * browser outlives nothing it started (the child is unreferenced).
 */
export function runLaunchers(
  commands: readonly LaunchCommand[],
  callbacks: LaunchCallbacks,
): void {
  const { onFailure, onSuccess, stopped } = callbacks;
  const attempt = (index: number, last: unknown): void => {
    const next = commands[index];
    if (next === undefined || stopped?.() === true) {
      onFailure(last);
      return;
    }
    let settled = false;
    const fallThrough = (error: unknown) => {
      if (settled) return;
      settled = true;
      attempt(index + 1, error);
    };
    try {
      const child = child_process.spawn(next.command, [...next.args], {
        stdio: 'ignore',
        windowsHide: true,
        ...(next.env === undefined
          ? {}
          : { env: { ...process.env, ...next.env } }),
      });
      const succeed = () => {
        if (settled) return;
        settled = true;
        onSuccess?.();
      };
      child.once('error', fallThrough);
      if (next.settlesOn === 'spawn') {
        child.once('spawn', succeed);
      } else {
        child.once('exit', (code) => {
          if (code === 0) succeed();
          else fallThrough(undefined);
        });
      }
      child.unref();
    } catch (error) {
      fallThrough(error);
    }
  };
  attempt(0, undefined);
}

/**
 * A launch that could not happen, in fixed words: `unknown`
 * `opening-browser`, with the launcher's code only when it is allowlisted —
 * never its message, its `spawnargs` (the URL) or a path.
 */
function launchFailure(error: unknown): AuthProviderFailure {
  return new AuthProviderFailure(classify(error, 'opening-browser'));
}

type OpenFunction = (
  url: string,
  options?: { app: { name: string | readonly string[] } },
) => Promise<unknown>;

/** `open`'s default export and its per-platform browser names, or nothing. */
async function loadOpen(): Promise<
  | {
      open: OpenFunction;
      apps: Partial<Record<NamedBrowser, string | readonly string[]>>;
    }
  | undefined
> {
  let loaded: unknown;
  try {
    loaded = await import('open');
  } catch {
    return undefined;
  }
  const open = readSafely(loaded, 'default');
  if (typeof open !== 'function') return undefined;
  // `open`'s per-platform names for each common browser. An `app.name` is an
  // executable name, and Chrome is no `chrome` on Linux (`google-chrome`,
  // `google-chrome-stable`, …): handing `open` the bare name failed with ENOENT.
  const apps = readSafely(loaded, 'apps');
  const name = (key: string): string | readonly string[] | undefined => {
    const value = readSafely(apps, key);
    return typeof value === 'string' || Array.isArray(value)
      ? (value as string | readonly string[])
      : undefined;
  };
  const names: Partial<Record<NamedBrowser, string | readonly string[]>> = {};
  for (const [browser, key] of [
    ['chrome', 'chrome'],
    ['msedge', 'edge'],
    ['firefox', 'firefox'],
  ] as const) {
    const value = name(key);
    if (value !== undefined) names[browser] = value;
  }
  return { open: open as OpenFunction, apps: names };
}

/**
 * Opens `url` in `browser` (the system's default when `undefined`) — the
 * launch every shipped `IBrowser` makes (§6a0):
 *
 * - only an `http(s)` URL is launched, as its serialisation; anything else
 *   starts nothing and rejects;
 * - nothing of the environment is guessed or changed: no `DISPLAY` is set
 *   (a given display, a remote browser or a console one is the consumer's
 *   own `IBrowser`);
 * - the `open` package when it loads — a named browser under `open`'s own
 *   per-platform names (`apps`), else its own name;
 * - without it, `launchCommands` through `runLaunchers`: an argument array,
 *   never a shell.
 *
 * Resolves once the browser was asked: a hand-off launcher exited `0`, a
 * browser binary started, or `open` resolved; rejects with an
 * `AuthProviderFailure` — `opening-browser` in fixed words, or `aborted`
 * when `signal` aborts first, which also starts no further launcher. A
 * started browser is never killed.
 */
export async function launchBrowser(
  browser: NamedBrowser | undefined,
  url: string,
  signal: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);
  // Only an http(s) URL, as its serialisation, is ever launched: it may
  // come from discovery or configuration.
  const href = launchableUrl(url);
  if (href === undefined) throw launchFailure(undefined);

  const loaded = await untilAborted(loadOpen(), signal);
  throwIfAborted(signal);
  if (loaded !== undefined) {
    const { open, apps } = loaded;
    const opened =
      browser === undefined
        ? open(href)
        : open(href, { app: { name: apps[browser] ?? browser } });
    try {
      await untilAborted(opened, signal);
    } catch (error) {
      if (signal.aborted) throw abortedFailure();
      throw launchFailure(error);
    }
    return;
  }

  // Without the `open` package: a launcher started with an argument array,
  // never a shell.
  const launched = new Promise<void>((resolve, reject) => {
    runLaunchers(launchCommands(process.platform, browser, href), {
      onSuccess: resolve,
      onFailure: (error) =>
        reject(signal.aborted ? abortedFailure() : launchFailure(error)),
      stopped: () => signal.aborted,
    });
  });
  await untilAborted(launched, signal);
}
