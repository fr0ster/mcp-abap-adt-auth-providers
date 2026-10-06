import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  ICertificateMaterial,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';

export interface RecordingTargetsOptions {
  /** false: the wire has no parameter logon (HTTP). */
  acceptsLogonParameters?: boolean;
  /** false: the wire has no TLS (RFC). */
  acceptsTls?: boolean;
  /** true: every target member throws — a broken wire. */
  throws?: boolean;
}

export function recordingTargets(options: RecordingTargetsOptions = {}) {
  const logon = {
    tls: [] as ICertificateMaterial[],
    params: [] as Record<string, string>[],
  };
  const request = {
    headers: {} as Record<string, string>,
    cookies: [] as string[],
  };
  const broken = () => {
    if (options.throws) throw new Error('target exploded: SECRET-IN-TARGET');
  };
  // As connection's targets answer (spec §7): minted by auth-errors.
  const refuse = (
    refused: 'tls-material' | 'logon-parameters',
  ): AuthOutcome => ({
    ok: false,
    refusal: authError['logon-target']({
      wire: refused === 'tls-material' ? 'rfc' : 'http',
      refused,
    }),
  });
  const logonTarget: ILogonTarget = {
    tlsMaterial(material) {
      broken();
      if (options.acceptsTls === false) return refuse('tls-material');
      logon.tls.push(material);
      return { ok: true };
    },
    logonParameters(parameters) {
      broken();
      if (options.acceptsLogonParameters === false)
        return refuse('logon-parameters');
      logon.params.push({ ...parameters });
      return { ok: true };
    },
  };
  const requestTarget: IRequestTarget = {
    header(name, value) {
      broken();
      request.headers[name] = value;
    },
    cookies(value) {
      broken();
      request.cookies.push(value);
    },
  };
  return { logonTarget, requestTarget, logon, request };
}
