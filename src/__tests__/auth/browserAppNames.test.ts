/**
 * A named browser reaches `open` under the names this platform installs it as.
 *
 * `open`'s `app.name` is an executable name, and `chrome` is no executable on
 * Linux — Chrome installs as `google-chrome`, `google-chrome-stable`, and so
 * on. `open` ships `apps`, the per-platform names of each common browser;
 * handing it a bare `'chrome'` failed with ENOENT, and the login never opened
 * (measured on Linux, 2026-10-03).
 */

import { jest } from '@jest/globals';

const openMock = jest.fn(async (_url: string, _opts?: unknown) => undefined);
const apps = {
  chrome: ['chrome-name-a', 'chrome-name-b'],
  edge: ['edge-name-a'],
  firefox: 'firefox-name',
};

jest.mock('open', () => ({
  __esModule: true,
  default: (url: string, opts?: unknown) => openMock(url, opts),
  apps,
}));

import { launchBrowser, type OpenableBrowser } from '../../auth/browserAuth';

const URL = 'https://idp.example/oauth/authorize?client_id=x';

async function appNameFor(browser: OpenableBrowser): Promise<unknown> {
  openMock.mockClear();
  await launchBrowser(URL, browser, () => {}, null);
  expect(openMock).toHaveBeenCalledTimes(1);
  const opts = openMock.mock.calls[0]![1] as { app?: { name?: unknown } };
  return opts?.app?.name;
}

describe('launchBrowser: a named browser', () => {
  it('chrome is handed to open as its per-platform names', async () => {
    expect(await appNameFor('chrome')).toEqual(apps.chrome);
  });

  it('msedge is handed to open as its per-platform names', async () => {
    expect(await appNameFor('msedge')).toEqual(apps.edge);
  });

  it('firefox is handed to open as its per-platform name', async () => {
    expect(await appNameFor('firefox')).toEqual(apps.firefox);
  });

  it('system opens the default browser, with no app', async () => {
    expect(await appNameFor('system')).toBeUndefined();
  });
});
