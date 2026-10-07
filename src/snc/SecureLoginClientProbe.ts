/**
 * Which SNC product is behind a library — so that a refused logon can say what
 * to do. A probe only names the product; it checks nothing. Measured: with the
 * Secure Login Client exited, an RFC open through its library starts the
 * client, which logs on (silently through SSO, or through its logon window),
 * so a "not running" refusal before logon would stop logons that succeed.
 * This one applies to a library inside the Secure Login Client's installation.
 */

import { win32 } from 'node:path';
import type { SncSystem } from './SncSystem';
import {
  MACOS_SLC_APP,
  SECURE_LOGIN_CLIENT,
  SLC_REGISTRY_KEY,
} from './secureLoginClient';

export interface ISncProductProbe {
  /** The product's name — for logs; a refusal names only the shipped probe's. */
  readonly product: string;
  /**
   * Whether the library at this path belongs to the product. `signal`, when
   * given, is the moment's: a probe that waits on the machine ends when it
   * aborts.
   */
  appliesTo(libraryPath: string, signal?: AbortSignal): Promise<boolean>;
}

function asDirectory(path: string): string {
  const normal = win32.normalize(path.trim()).toLowerCase();
  return normal.endsWith('\\') ? normal : `${normal}\\`;
}

export class SecureLoginClientProbe implements ISncProductProbe {
  readonly product = SECURE_LOGIN_CLIENT;

  constructor(private readonly system: SncSystem) {}

  async appliesTo(libraryPath: string, signal?: AbortSignal): Promise<boolean> {
    const { system } = this;
    if (system.platform === 'win32') {
      const dirs = await Promise.all(
        ['InstallPath64', 'InstallPath32'].map((name) =>
          system.readRegistryValue(SLC_REGISTRY_KEY, name, signal),
        ),
      );
      const library = win32.normalize(libraryPath.trim()).toLowerCase();
      return dirs.some(
        (dir) =>
          typeof dir === 'string' &&
          dir.trim() !== '' &&
          library.startsWith(asDirectory(dir)),
      );
    }
    if (system.platform === 'darwin')
      return libraryPath.startsWith(MACOS_SLC_APP);
    return false;
  }
}
