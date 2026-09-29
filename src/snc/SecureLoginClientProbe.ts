/**
 * Is the SNC product behind a library ready? A probe applies only to a library
 * it recognises — this one to a library inside the Secure Login Client's
 * installation — so another SNC product is never refused for lacking a
 * process it does not have. It checks that the client runs, not that a
 * profile is logged on: no documented interface says so.
 */

import { win32 } from 'node:path';
import { ValidationError } from '../errors/TokenProviderErrors';
import type { SncSystem } from './SncSystem';
import {
  MACOS_SLC_APP,
  SECURE_LOGIN_CLIENT,
  SLC_REGISTRY_KEY,
} from './secureLoginClient';

export interface ISncProductProbe {
  readonly product: string;
  appliesTo(libraryPath: string): Promise<boolean>;
  /** Throws when the product is not usable. */
  check(): Promise<void>;
}

function asDirectory(path: string): string {
  const normal = win32.normalize(path.trim()).toLowerCase();
  return normal.endsWith('\\') ? normal : `${normal}\\`;
}

export class SecureLoginClientProbe implements ISncProductProbe {
  readonly product = SECURE_LOGIN_CLIENT;

  constructor(private readonly system: SncSystem) {}

  async appliesTo(libraryPath: string): Promise<boolean> {
    const { system } = this;
    if (system.platform === 'win32') {
      const dirs = await Promise.all(
        ['InstallPath64', 'InstallPath32'].map((name) =>
          system.readRegistryValue(SLC_REGISTRY_KEY, name),
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

  async check(): Promise<void> {
    let names: string[];
    try {
      names = await this.system.listProcessNames();
    } catch {
      // The listing tool's own message is foreign text; it stays out.
      throw new ValidationError(
        `Could not check whether the ${SECURE_LOGIN_CLIENT} is running (the process list could not be read).`,
      );
    }
    const windows = this.system.platform === 'win32';
    const running = windows
      ? names.some((name) => name.toLowerCase() === 'sbus.exe')
      : names.some((name) => name.startsWith(MACOS_SLC_APP));
    if (!running) {
      throw new ValidationError(
        `The ${SECURE_LOGIN_CLIENT} is not running (${windows ? 'sbus.exe' : 'Secure Login Client.app'} not found).`,
      );
    }
  }
}
