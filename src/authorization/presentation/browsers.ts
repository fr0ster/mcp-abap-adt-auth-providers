/**
 * The shipped browsers (spec §6d): each implements `IBrowser` with the
 * launch as built (§6a0, `src/auth/browserLaunch.ts`) — the `open` package
 * when it loads, else a launcher started with an argument array and no
 * shell; only an `http(s)` URL is launched, as its serialisation. A browser
 * not listed here is the consumer's own `IBrowser`; no browser is named by a
 * string, so nothing is validated at run time.
 *
 * `open(url, signal)` resolves once the browser was asked to open the URL
 * and rejects with an `AuthProviderFailure` when it could not be
 * (`opening-browser`, in fixed words) or when `signal` aborted first.
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
 * The system's default browser: `open(url)`; without the `open` package
 * `xdg-open` (Linux), `open` (macOS), `rundll32 url.dll,FileProtocolHandler`
 * (Windows).
 */
export function systemBrowser(): IBrowser {
  return shipped(undefined);
}

/**
 * Google Chrome: `open`'s per-platform Chrome names; without the package
 * `google-chrome`, `chromium`, `chromium-browser` (Linux), `open -a "Google
 * Chrome"` (macOS), `Start-Process chrome` (Windows).
 */
export function chromeBrowser(): IBrowser {
  return shipped('chrome');
}

/**
 * Microsoft Edge: `open`'s per-platform Edge names; without the package
 * `microsoft-edge`, `microsoft-edge-stable` (Linux), `open -a "Microsoft
 * Edge"` (macOS), `Start-Process msedge` (Windows).
 */
export function edgeBrowser(): IBrowser {
  return shipped('msedge');
}

/**
 * Firefox: `open`'s per-platform Firefox names; without the package
 * `firefox`, `firefox-esr` (Linux), `open -a Firefox` (macOS),
 * `Start-Process firefox` (Windows).
 */
export function firefoxBrowser(): IBrowser {
  return shipped('firefox');
}
