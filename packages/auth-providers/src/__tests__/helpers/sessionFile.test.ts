/**
 * Which session file the live tests read, and whether they may open a browser.
 * Both take their environment as arguments, so every platform's case runs here.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { interactiveLoginEnabled, resolveSessionFile } from './configHelpers';

const unix = {
  platform: 'linux' as NodeJS.Platform,
  homeDir: '/home/u',
  projectRoot: '/work/repo',
};

describe('resolveSessionFile', () => {
  it('prefers MCP_ABAP_ADT_SESSION_FILE over session_path and the default', () => {
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: { MCP_ABAP_ADT_SESSION_FILE: '/any/where/my.env' },
        config: { destination: 'trial', session_path: '/other.env' },
      }),
      '/any/where/my.env',
    );
  });

  it('prefers session_path over the standard folder', () => {
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { destination: 'trial', session_path: '/abs/s.env' },
      }),
      '/abs/s.env',
    );
  });

  it('expands ~ in session_path and in the environment variable', () => {
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { session_path: '~/tokens/s.env' },
      }),
      '/home/u/tokens/s.env',
    );
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: { MCP_ABAP_ADT_SESSION_FILE: '~/e.env' },
        config: {},
      }),
      '/home/u/e.env',
    );
  });

  it('resolves a relative session_path against the project root', () => {
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { session_path: 'tests/s.env' },
      }),
      '/work/repo/tests/s.env',
    );
  });

  it('defaults to ~/.config/mcp-abap-adt/sessions/<destination>.env on Unix', () => {
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { destination: 'trial' },
      }),
      '/home/u/.config/mcp-abap-adt/sessions/trial.env',
    );
  });

  it('defaults to Documents/mcp-abap-adt/sessions/<destination>.env on Windows', () => {
    assert.equal(
      resolveSessionFile({
        platform: 'win32',
        homeDir: 'C:\\Users\\u',
        projectRoot: 'C:\\work\\repo',
        env: {},
        config: { destination: 'trial' },
      }),
      'C:\\Users\\u\\Documents\\mcp-abap-adt\\sessions\\trial.env',
    );
  });

  it('honours destination_dir, ~ included', () => {
    assert.equal(
      resolveSessionFile({
        ...unix,
        env: {},
        config: { destination: 'trial', destination_dir: '~/cfg' },
      }),
      '/home/u/cfg/sessions/trial.env',
    );
  });

  it('has no file to offer without a destination or an explicit path', () => {
    assert.equal(resolveSessionFile({ ...unix, env: {}, config: {} }), null);
  });
});

describe('interactiveLoginEnabled', () => {
  it('is off by default', () => {
    assert.equal(interactiveLoginEnabled({ env: {}, config: {} }), false);
  });

  it('is on with interactive_login: true', () => {
    assert.equal(
      interactiveLoginEnabled({ env: {}, config: { interactive_login: true } }),
      true,
    );
  });

  it('is on with MCP_ABAP_ADT_INTERACTIVE=1, and only with 1', () => {
    assert.equal(
      interactiveLoginEnabled({
        env: { MCP_ABAP_ADT_INTERACTIVE: '1' },
        config: {},
      }),
      true,
    );
    assert.equal(
      interactiveLoginEnabled({
        env: { MCP_ABAP_ADT_INTERACTIVE: '0' },
        config: {},
      }),
      false,
    );
  });
});
