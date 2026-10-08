/**
 * The shipped browsers (spec §6d): six factories, each ONE fixed launch —
 * no platform switch, no fallback chain, no platform check. Each runs
 * exactly its program; on another OS it does whatever a program of that
 * name does there — where there is none, the launch fails to start and
 * rejects (the composer then shows the URL once and the login waits); where
 * there is one (Debian's `/usr/bin/open` is `xdg-open` or `run-mailcap`),
 * that program runs. The consumer picks the one for its platform.
 * Anything else — a remote Chrome, a console browser, WSL, a given DISPLAY —
 * is the consumer's own `IBrowser`.
 *
 * Every launch is a program started with an argument array, never a shell
 * (§6a0, `src/auth/browserLaunch.ts`); a program or app name is passed as
 * given; only an `http(s)` URL is launched, as its serialisation.
 * `open(url, signal)` resolves once the browser was asked — a hand-off
 * launcher at its exit `0`, a browser binary at its `spawn` — and rejects
 * with an `AuthProviderFailure` (`opening-browser` in fixed words, or
 * `aborted`); no real `AbortSignal` rejects before anything starts. A
 * started browser is never killed. Outside a composition the caller owns
 * the signal: a hand-off launcher that never exits (`xdg-open` in its
 * generic mode waits for the browser) keeps `open()` pending, and the
 * process alive, until it exits or the signal aborts.
 */

import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';
import {
  type LaunchFor,
  launchBrowser,
  linuxDefaultLaunch,
  linuxLaunch,
  macDefaultLaunch,
  macLaunch,
  windowsDefaultLaunch,
  windowsLaunch,
} from '../../auth/browserLaunch';

function shipped(launch: LaunchFor): IBrowser {
  return Object.freeze({
    open: (url: string, signal: AbortSignal): Promise<void> =>
      launchBrowser(launch, url, signal),
  });
}

/** Linux's default browser: `xdg-open <url>`, settled at its exit `0`. */
export function linuxDefaultBrowser(): IBrowser {
  return shipped(linuxDefaultLaunch);
}

/**
 * A browser binary on Linux: `<executable> <url>` — a name on `PATH` or an
 * absolute path, as given (`'google-chrome'`, `'firefox'`,
 * `'/opt/…/microsoft-edge'`); resolved at its `spawn`, its exit never awaited.
 */
export function linuxBrowser(executable: string): IBrowser {
  return shipped(linuxLaunch(executable));
}

/** macOS's default browser: `open <url>`, settled at its exit `0`. */
export function macDefaultBrowser(): IBrowser {
  return shipped(macDefaultLaunch);
}

/**
 * An application on macOS: `open -a <app> <url>` (`'Google Chrome'`,
 * `'Microsoft Edge'`, `'Firefox'`), settled at its exit `0`.
 */
export function macBrowser(app: string): IBrowser {
  return shipped(macLaunch(app));
}

/**
 * Windows' default browser: `%SystemRoot%\System32\rundll32.exe
 * url.dll,FileProtocolHandler <url>`, settled at its exit `0`.
 */
export function windowsDefaultBrowser(): IBrowser {
  return shipped(windowsDefaultLaunch);
}

/**
 * A program on Windows (`'chrome'`, `'msedge'`, `'firefox'`, or a path):
 * `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe
 * -NoProfile -NonInteractive -Command` with the fixed text `Start-Process
 * -FilePath $env:MCP_ABAP_ADT_BROWSER_PROGRAM -ArgumentList
 * $env:MCP_ABAP_ADT_AUTHORIZATION_URL` — the program and the URL only in the
 * environment, never in the command text. Settled at its exit `0`.
 */
export function windowsBrowser(program: string): IBrowser {
  return shipped(windowsLaunch(program));
}
