import { readFile } from 'node:fs/promises';
import { authError } from '@mcp-abap-adt/auth-errors';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import type {
  ICertificateMaterialLoader,
  ISapConfig,
} from '@mcp-abap-adt/interfaces-auth-sap';
import { misconfigured } from '../auth/configuration';

export class FileCertificateMaterialLoader
  implements ICertificateMaterialLoader
{
  async load(config: ISapConfig): Promise<ICertificateMaterial> {
    const hasPem = !!(config.certPath || config.certKeyPath); // any PEM-style field present
    const hasPfx = !!config.certPfxPath;
    if (hasPem && hasPfx) {
      throw misconfigured(
        authError.configuration({
          case: 'certificate-pem-and-pfx',
          fields: ['certPath', 'certPfxPath'],
        }),
      );
    }
    if (hasPfx) {
      return {
        pfx: await readFile(config.certPfxPath as string),
        passphrase: config.certPassphrase,
      };
    }
    if (config.certPath && config.certKeyPath) {
      return {
        cert: await readFile(config.certPath),
        key: await readFile(config.certKeyPath),
        passphrase: config.certPassphrase,
      };
    }
    throw misconfigured(
      authError.configuration({
        case: 'certificate-files-missing',
        fields: ['certPfxPath', 'certPath', 'certKeyPath'],
      }),
    );
  }
}
