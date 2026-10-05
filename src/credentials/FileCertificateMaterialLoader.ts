import { readFile } from 'node:fs/promises';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import type {
  ICertificateMaterialLoader,
  ISapConfig,
} from '@mcp-abap-adt/interfaces-auth-sap';
import { ValidationError } from '../errors/TokenProviderErrors';

/** The passphrase, only when the configuration states one. */
function passphraseOf(config: ISapConfig): { passphrase?: string } {
  const { certPassphrase } = config;
  return certPassphrase === undefined ? {} : { passphrase: certPassphrase };
}

export class FileCertificateMaterialLoader
  implements ICertificateMaterialLoader
{
  async load(config: ISapConfig): Promise<ICertificateMaterial> {
    const hasPem = !!(config.certPath || config.certKeyPath); // any PEM-style field present
    const hasPfx = !!config.certPfxPath;
    if (hasPem && hasPfx) {
      throw new ValidationError(
        'Certificate auth: provide either PEM (certPath+certKeyPath) OR certPfxPath, not both.',
        ['certPath', 'certPfxPath'],
      );
    }
    if (hasPfx) {
      return {
        pfx: await readFile(config.certPfxPath as string),
        ...passphraseOf(config),
      };
    }
    if (config.certPath && config.certKeyPath) {
      return {
        cert: await readFile(config.certPath),
        key: await readFile(config.certKeyPath),
        ...passphraseOf(config),
      };
    }
    throw new ValidationError(
      'Certificate auth requires certPfxPath OR (certPath AND certKeyPath).',
      ['certPfxPath', 'certPath', 'certKeyPath'],
    );
  }
}
