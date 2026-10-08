/**
 * The shipped browsers (spec §6d): each implements `IBrowser` through the
 * package's own launchers on every platform (§6a0, `src/auth/browserLaunch.ts`;
 * no `open` package) — a program started with an argument array, never a
 * shell; only an `http(s)` URL is launched, as its serialisation. A browser
 * not listed here is the consumer's own `IBrowser`; no browser is named by a
 * string, so nothing is validated at run time.
 *
 * `open(url, signal)` resolves once the browser was asked: a hand-off
 * launcher (`xdg-open`, `open(1)`, `rundll32`, PowerShell's `Start-Process`)
 * at its exit `0` — a non-zero exit or an error is a failure, the next
 * launcher tried; a browser binary started directly at its `spawn`, its exit
 * never awaited. It rejects with an `AuthProviderFailure` when no launcher
 * answered (`opening-browser`, in fixed words) or `aborted` when `signal`
 * aborted first. A started browser is never killed.
 */

import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';
import { launchBrowser, type NamedBrowser } from '../../auth/browserLaunch';

function shipped(browser: NamedBrowser | undefined): IBrowser {
  return Object.freeze({
    open: (url: string, signal: AbortSignal): Promise<void> =>
      launchBrowser(browser, url, signal),
  });
}

/**
 * The system's default browser: `xdg-open` (Linux), `open` (macOS),
 * `rundll32 url.dll,FileProtocolHandler`
 * (Windows).
 */
export function systemBrowser(): IBrowser {
  return shipped(undefined);
}

/**
 * Google Chrome: `google-chrome`, `chromium`, `chromium-browser` (Linux), `open -a "Google
 * Chrome"` (macOS), `Start-Process chrome` (Windows).
 */
export function chromeBrowser(): IBrowser {
  return shipped('chrome');
}

/**
 * Microsoft Edge: `microsoft-edge`, `microsoft-edge-stable` (Linux), `open -a "Microsoft
 * Edge"` (macOS), `Start-Process msedge` (Windows).
 */
export function edgeBrowser(): IBrowser {
  return shipped('msedge');
}

/**
 * Firefox: `firefox`, `firefox-esr` (Linux), `open -a Firefox` (macOS),
 * `Start-Process firefox` (Windows).
 */
export function firefoxBrowser(): IBrowser {
  return shipped('firefox');
}
