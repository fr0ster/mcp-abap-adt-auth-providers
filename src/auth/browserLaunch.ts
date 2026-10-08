/**
 * Opening the authorization URL — no shell, ever. Each shipped `IBrowser`
 * (`browsers.ts`) is ONE fixed launch, built here from its `LaunchCommand`
 * and started by `launchBrowser`: no platform switch, no fallback chain, no
 * platform check (on another OS the launch simply fails to start).
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
 * - every launch is a program started with an argument array
 *   (`child_process.spawn`, no `shell` option): the URL is one element of
 *   argv, which no shell parses; a consumer's program or app name is passed
 *   as given, also as one element;
 * - on Windows the launchers are the system's own, by absolute path under
 *   `%SystemRoot%\System32` (a bare name is searched in the current
 *   directory first), and the URL must hold no quote, space, `<`, `>`, `^`,
 *   `|`, backslash or control character and a valid host — reasoned from
 *   ShellExecute's parsing, not measured on a Windows host;
 * - on Windows `cmd /c start` is never used, since `cmd` parses `&`, `|`,
 *   `^` and `%` in its command line whatever the quoting. The default browser
 *   is opened by `rundll32 url.dll,FileProtocolHandler <url>`, which hands the
 *   rest of its command line to `ShellExecute` as the URL and runs no command
 *   interpreter. A named program needs `ShellExecute`'s App Paths lookup
 *   (`chrome` is not on `PATH`), so it is started by PowerShell's
 *   `Start-Process` with a fixed command text; the program and the URL reach
 *   it through environment variables, never through PowerShell's parser.
 */

import * as child_process from 'node:child_process';
import { win32 } from 'node:path';
import { AuthProviderFailure, classify } from '@mcp-abap-adt/auth-errors';
import { abortedFailure, throwIfAborted, untilAborted } from './attempt';

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
  /** Extra environment for the launcher (`windowsBrowser`). */
  readonly env?: Readonly<Record<string, string>>;
}

/** The variable PowerShell reads the URL from (`windowsBrowser`). */
export const URL_VARIABLE = 'MCP_ABAP_ADT_AUTHORIZATION_URL';

/** The variable PowerShell reads the program from (`windowsBrowser`). */
export const PROGRAM_VARIABLE = 'MCP_ABAP_ADT_BROWSER_PROGRAM';

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

/** One fixed launch for `href` (already `launchableUrl`). */
export type LaunchFor = (href: string) => LaunchCommand;

/** `xdg-open <url>`: a hand-off launcher. */
export const linuxDefaultLaunch: LaunchFor = (href) => ({
  command: 'xdg-open',
  args: [href],
  settlesOn: 'exit',
});

/** `<executable> <url>`: a browser binary, started directly. */
export const linuxLaunch =
  (executable: string): LaunchFor =>
  (href) => ({ command: executable, args: [href], settlesOn: 'spawn' });

/** `open <url>`: macOS's hand-off launcher. */
export const macDefaultLaunch: LaunchFor = (href) => ({
  command: 'open',
  args: [href],
  settlesOn: 'exit',
});

/** `open -a <app> <url>`. */
export const macLaunch =
  (app: string): LaunchFor =>
  (href) => ({ command: 'open', args: ['-a', app, href], settlesOn: 'exit' });

/** `System32\rundll32.exe url.dll,FileProtocolHandler <url>`. */
export const windowsDefaultLaunch: LaunchFor = (href) => ({
  command: system32('rundll32.exe'),
  args: ['url.dll,FileProtocolHandler', href],
  settlesOn: 'exit',
});

/**
 * PowerShell's `Start-Process` with a fixed command text: the program and
 * the URL are read from the environment at run time, never interpolated.
 */
export const windowsLaunch =
  (program: string): LaunchFor =>
  (href) => ({
    command: system32('WindowsPowerShell', 'v1.0', 'powershell.exe'),
    args: [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `Start-Process -FilePath $env:${PROGRAM_VARIABLE} -ArgumentList $env:${URL_VARIABLE}`,
    ],
    env: { [PROGRAM_VARIABLE]: program, [URL_VARIABLE]: href },
    settlesOn: 'exit',
  });

/** How `runLauncher` reports, and whether it may still start. */
export interface LaunchCallbacks {
  /** Called once, with the launcher's error (`undefined` for a non-zero exit), when it did not answer. */
  readonly onFailure: (error: unknown) => void;
  /** Called once when the launcher answered: exited `0`, or started (`settlesOn: 'spawn'`). */
  readonly onSuccess?: (() => void) | undefined;
  /** Checked before the start: `true` starts nothing and fails. */
  readonly stopped?: (() => boolean) | undefined;
}

/**
 * Starts ONE launcher, without a shell — there is no next candidate.
 * `onSuccess` is called once when it answers: a hand-off launcher by
 * exiting `0`, a browser binary by starting (its exit is never awaited);
 * `onFailure` once otherwise — with its error when it could not start, or
 * `undefined` for a non-zero exit — and at once, starting nothing, when
 * `stopped()` says so. Never throws; the browser outlives nothing it started
 * (the child is unreferenced, never killed).
 */
export function runLauncher(
  launch: LaunchCommand,
  callbacks: LaunchCallbacks,
): void {
  const { onFailure, onSuccess, stopped } = callbacks;
  if (stopped?.() === true) {
    onFailure(undefined);
    return;
  }
  let settled = false;
  const settle = (answer: () => void) => {
    if (settled) return;
    settled = true;
    answer();
  };
  const fail = (error: unknown) => settle(() => onFailure(error));
  try {
    const child = child_process.spawn(launch.command, [...launch.args], {
      stdio: 'ignore',
      windowsHide: true,
      ...(launch.env === undefined
        ? {}
        : { env: { ...process.env, ...launch.env } }),
    });
    const succeed = () => settle(() => onSuccess?.());
    child.once('error', fail);
    if (launch.settlesOn === 'spawn') {
      child.once('spawn', succeed);
    } else {
      child.once('exit', (code) => {
        if (code === 0) succeed();
        else fail(undefined);
      });
    }
    child.unref();
  } catch (error) {
    fail(error);
  }
}

/**
 * A launch that could not happen, in fixed words: `unknown`
 * `opening-browser`, with the launcher's code only when it is allowlisted —
 * never its message, its `spawnargs` (the URL) or a path.
 */
function launchFailure(error: unknown): AuthProviderFailure {
  return new AuthProviderFailure(classify(error, 'opening-browser'));
}

/**
 * Opens `url` with one fixed launch — the one every shipped `IBrowser` makes
 * (§6a0):
 *
 * - only an `http(s)` URL is launched, as its serialisation; anything else
 *   starts nothing and rejects;
 * - nothing of the environment is guessed or changed (a given display, a
 *   remote browser or a console one is the consumer's own `IBrowser`);
 * - one program, an argument array, never a shell; no next candidate.
 *
 * Resolves once the browser was asked: a hand-off launcher exited `0`, or a
 * browser binary started; rejects with an `AuthProviderFailure` —
 * `opening-browser` in fixed words (a non-zero exit, an error before the
 * start), or `aborted` when `signal` aborts first. A started browser is
 * never killed.
 */
export async function launchBrowser(
  launch: LaunchFor,
  url: string,
  signal: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);
  // Only an http(s) URL, as its serialisation, is ever launched: it may
  // come from discovery or configuration.
  const href = launchableUrl(url);
  if (href === undefined) throw launchFailure(undefined);

  const launched = new Promise<void>((resolve, reject) => {
    runLauncher(launch(href), {
      onSuccess: resolve,
      onFailure: (error) =>
        reject(signal.aborted ? abortedFailure() : launchFailure(error)),
      stopped: () => signal.aborted,
    });
  });
  await untilAborted(launched, signal);
}
