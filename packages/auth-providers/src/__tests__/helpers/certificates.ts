/** The committed test certificates (`fixtures/certificates`), as material. */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import { certificateThumbprint } from '../../auth/certificateMaterial';

const dir = join(__dirname, '..', 'fixtures', 'certificates');
const read = (name: string) => readFileSync(join(dir, name));

/** `client.crt` / `client.key`. */
export function certificate(): ICertificateMaterial {
  return { cert: read('client.crt'), key: read('client.key') };
}

/** `other.crt` / `other.key`. */
export function otherCertificate(): ICertificateMaterial {
  return { cert: read('other.crt'), key: read('other.key') };
}

export const thumbprintOf = certificateThumbprint;
