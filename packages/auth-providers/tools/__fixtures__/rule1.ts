// Rule 1: a provider that does not reach AuthProviderBase — by `implements`,
// and structurally. Must be found, both.
import { OK } from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome, IAuthProvider } from '@mcp-abap-adt/interfaces-auth';

export class Declared implements IAuthProvider {
  readonly kind = 'declared';
  async prepare(): Promise<AuthOutcome> {
    return OK;
  }
  async establish(): Promise<AuthOutcome> {
    return OK;
  }
  async authorize(): Promise<AuthOutcome> {
    return OK;
  }
  async rejected(): Promise<AuthOutcome> {
    return OK;
  }
}

export class Structural {
  readonly kind = 'structural';
  async prepare(): Promise<AuthOutcome> {
    return OK;
  }
  async establish(): Promise<AuthOutcome> {
    return OK;
  }
  async authorize(): Promise<AuthOutcome> {
    return OK;
  }
  async rejected(): Promise<AuthOutcome> {
    return OK;
  }
}
