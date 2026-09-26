/**
 * Which session file the live tests read, and whether they may open a browser.
 * Both take their environment as arguments, so every platform's case runs here.
 */

import { describe, expect, it } from '@jest/globals';
import { interactiveLoginEnabled, resolveSessionFile } from './configHelpers';

const unix = {
  platform: 'linux' as NodeJS.Platform,
  homeDir: '/home/u',
  projectRoot: '/work/repo',
};

describe('resolveSessionFile', () => {
  it('prefers MCP_ABAP_ADT_SESSION_FILE over session_path and the default', () => {
    expect(
      resolveSessionFile({
        ...unix,
        env: { MCP_ABAP_ADT_SESSION_FILE: '/any/where/my.env' },
        config: { destination: 'trial', session_path: '/other.env' },
      }),
    ).toBe('/any/where/my.env');
  });

  it('prefers session_path over the standard folder', () => {
    expect(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { destination: 'trial', session_path: '/abs/s.env' },
      }),
    ).toBe('/abs/s.env');
  });

  it('expands ~ in session_path and in the environment variable', () => {
    expect(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { session_path: '~/tokens/s.env' },
      }),
    ).toBe('/home/u/tokens/s.env');
    expect(
      resolveSessionFile({
        ...unix,
        env: { MCP_ABAP_ADT_SESSION_FILE: '~/e.env' },
        config: {},
      }),
    ).toBe('/home/u/e.env');
  });

  it('resolves a relative session_path against the project root', () => {
    expect(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { session_path: 'tests/s.env' },
      }),
    ).toBe('/work/repo/tests/s.env');
  });

  it('defaults to ~/.config/mcp-abap-adt/sessions/<destination>.env on Unix', () => {
    expect(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { destination: 'trial' },
      }),
    ).toBe('/home/u/.config/mcp-abap-adt/sessions/trial.env');
  });

  it('defaults to Documents/mcp-abap-adt/sessions/<destination>.env on Windows', () => {
    expect(
      resolveSessionFile({
        platform: 'win32',
        homeDir: 'C:\\Users\\u',
        projectRoot: 'C:\\work\\repo',
        env: {},
        config: { destination: 'trial' },
      }),
    ).toBe('C:\\Users\\u\\Documents\\mcp-abap-adt\\sessions\\trial.env');
  });

  it('honours destination_dir, ~ included', () => {
    expect(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { destination: 'trial', destination_dir: '~/cfg' },
      }),
    ).toBe('/home/u/cfg/sessions/trial.env');
  });

  it('has no file to offer without a destination or an explicit path', () => {
    expect(resolveSessionFile({ ...unix, env: {}, config: {} })).toBeNull();
  });
});

describe('interactiveLoginEnabled', () => {
  it('is off by default', () => {
    expect(interactiveLoginEnabled({ env: {}, config: {} })).toBe(false);
  });

  it('is on with interactive_login: true', () => {
    expect(
      interactiveLoginEnabled({ env: {}, config: { interactive_login: true } }),
    ).toBe(true);
  });

  it('is on with MCP_ABAP_ADT_INTERACTIVE=1, and only with 1', () => {
    expect(
      interactiveLoginEnabled({
        env: { MCP_ABAP_ADT_INTERACTIVE: '1' },
        config: {},
      }),
    ).toBe(true);
    expect(
      interactiveLoginEnabled({
        env: { MCP_ABAP_ADT_INTERACTIVE: '0' },
        config: {},
      }),
    ).toBe(false);
  });
});
