/**
 * Reading a Negotiate token: which mechanism is it, Kerberos, NTLM, or neither
 * that can be read (spec §4.3).
 *
 * Plain code over the decoded bytes, no regular expression. The base64 alphabet
 * is checked character by character; DER is read with definite lengths only
 * (at most four length bytes), every length checked against what remains of its
 * container, through the fixed levels of the structure and no deeper:
 *
 *   GSS frame   60 L { 06 L oid, inner }                    (RFC 2743 §3.1)
 *   NegTokenInit = GSS frame with oid 1.3.6.1.5.5.2 whose inner is
 *     A0 L { 30 L { A0 L { 30 L { 06 oid ... } }          mechTypes
 *                   [A1 reqFlags] [A2 L { 04 L mechToken }] [A3 mechListMIC] } }
 *                                                           (RFC 4178 §4.2)
 *
 * A malformed structure is 'unreadable'; nothing is thrown. The reader is
 * iterative over a flat structure, so its work is linear in the input.
 */

export type NegotiateMechanism = 'kerberos' | 'ntlm' | 'unreadable';

const BASE64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const TAG_GSS = 0x60;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_OCTET_STRING = 0x04;
const TAG_NEG_TOKEN_INIT = 0xa0;
const TAG_MECH_TYPES = 0xa0;
const TAG_MECH_TOKEN = 0xa2;

const NTLM_SIGNATURE = Buffer.from('NTLMSSP\0', 'latin1');
// 1.2.840.113554.1.2.2, 1.2.840.48018.1.2.2 (legacy Microsoft), 1.3.6.1.5.5.2
const OID_KRB5 = Buffer.from([
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
]);
const OID_KRB5_MS = Buffer.from([
  0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
]);
const OID_SPNEGO = Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);

interface Span {
  readonly tag: number;
  readonly start: number; // first content byte
  readonly end: number; // one past the last content byte
}

function decodeBase64(token: unknown): Buffer | undefined {
  if (typeof token !== 'string' || token.length === 0) return undefined;
  if (token.length % 4 !== 0) return undefined;
  let padding = 0;
  for (let i = 0; i < token.length; i++) {
    const c = token.charAt(i);
    if (c === '=') {
      // only the last one or two characters
      if (i < token.length - 2) return undefined;
      padding++;
    } else if (padding > 0 || !BASE64_ALPHABET.includes(c)) {
      return undefined;
    }
  }
  return Buffer.from(token, 'base64');
}

/** One TLV in [pos, limit): definite length of up to four length bytes. */
function readTlv(bytes: Buffer, pos: number, limit: number): Span | undefined {
  if (pos + 2 > limit) return undefined;
  const tag = bytes[pos];
  const first = bytes[pos + 1];
  if (tag === undefined || first === undefined) return undefined;
  let length: number;
  let start: number;
  if (first < 0x80) {
    length = first;
    start = pos + 2;
  } else {
    const count = first & 0x7f;
    // 0x80 is the indefinite form; more than four length bytes is refused
    if (count === 0 || count > 4) return undefined;
    if (pos + 2 + count > limit) return undefined;
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + (bytes[pos + 2 + i] ?? 0);
    }
    start = pos + 2 + count;
  }
  if (length > limit - start) return undefined;
  return { tag, start, end: start + length };
}

function equals(bytes: Buffer, span: Span, oid: Buffer): boolean {
  return (
    span.end - span.start === oid.length &&
    bytes.compare(oid, 0, oid.length, span.start, span.end) === 0
  );
}

function startsWithNtlm(bytes: Buffer, from: number, to: number): boolean {
  return (
    to - from >= NTLM_SIGNATURE.length &&
    bytes.compare(
      NTLM_SIGNATURE,
      0,
      NTLM_SIGNATURE.length,
      from,
      from + NTLM_SIGNATURE.length,
    ) === 0
  );
}

interface Frame {
  readonly oid: Span;
  readonly innerStart: number;
  readonly innerEnd: number;
}

/** A GSS-framed token filling [from, to) exactly. */
function readFrame(bytes: Buffer, from: number, to: number): Frame | undefined {
  const outer = readTlv(bytes, from, to);
  if (outer === undefined || outer.tag !== TAG_GSS || outer.end !== to) {
    return undefined;
  }
  const oid = readTlv(bytes, outer.start, outer.end);
  if (oid === undefined || oid.tag !== TAG_OID || oid.end === oid.start) {
    return undefined;
  }
  return { oid, innerStart: oid.end, innerEnd: outer.end };
}

function isKerberosOid(bytes: Buffer, oid: Span): boolean {
  return equals(bytes, oid, OID_KRB5) || equals(bytes, oid, OID_KRB5_MS);
}

/** A Kerberos GSS token: the frame with a Kerberos OID and its 2-byte token id. */
function isGssKerberos(bytes: Buffer, from: number, to: number): boolean {
  const frame = readFrame(bytes, from, to);
  return (
    frame !== undefined &&
    isKerberosOid(bytes, frame.oid) &&
    frame.innerEnd - frame.innerStart >= 2
  );
}

/** The span a TLV of the wanted tag fills exactly inside [from, to). */
function filling(
  bytes: Buffer,
  from: number,
  to: number,
  tag: number,
): Span | undefined {
  const span = readTlv(bytes, from, to);
  return span !== undefined && span.tag === tag && span.end === to
    ? span
    : undefined;
}

function readNegTokenInit(
  bytes: Buffer,
  from: number,
  to: number,
): NegotiateMechanism {
  const wrapper = filling(bytes, from, to, TAG_NEG_TOKEN_INIT);
  if (wrapper === undefined) return 'unreadable';
  const init = filling(bytes, wrapper.start, wrapper.end, TAG_SEQUENCE);
  if (init === undefined) return 'unreadable';

  // [0] mechTypes comes first.
  const typesField = readTlv(bytes, init.start, init.end);
  if (typesField === undefined || typesField.tag !== TAG_MECH_TYPES) {
    return 'unreadable';
  }
  const types = filling(bytes, typesField.start, typesField.end, TAG_SEQUENCE);
  if (types === undefined) return 'unreadable';

  let firstIsKerberos = false;
  let count = 0;
  for (let pos = types.start; pos < types.end; ) {
    const oid = readTlv(bytes, pos, types.end);
    if (oid === undefined || oid.tag !== TAG_OID) return 'unreadable';
    if (count === 0) firstIsKerberos = isKerberosOid(bytes, oid);
    count++;
    pos = oid.end;
  }
  if (count === 0) return 'unreadable';

  // The remaining fields; [2] mechToken at most once.
  let token: Span | undefined;
  for (let pos = typesField.end; pos < init.end; ) {
    const field = readTlv(bytes, pos, init.end);
    if (field === undefined) return 'unreadable';
    if (field.tag === TAG_MECH_TOKEN) {
      if (token !== undefined) return 'unreadable';
      token = filling(bytes, field.start, field.end, TAG_OCTET_STRING);
      if (token === undefined) return 'unreadable';
    }
    pos = field.end;
  }
  if (token === undefined) return 'unreadable';

  if (startsWithNtlm(bytes, token.start, token.end)) return 'ntlm';
  if (firstIsKerberos && isGssKerberos(bytes, token.start, token.end)) {
    return 'kerberos';
  }
  return 'unreadable';
}

function read(bytes: Buffer): NegotiateMechanism {
  if (startsWithNtlm(bytes, 0, bytes.length)) return 'ntlm';
  const frame = readFrame(bytes, 0, bytes.length);
  if (frame === undefined) return 'unreadable';
  if (isKerberosOid(bytes, frame.oid)) {
    return frame.innerEnd - frame.innerStart >= 2 ? 'kerberos' : 'unreadable';
  }
  if (equals(bytes, frame.oid, OID_SPNEGO)) {
    return readNegTokenInit(bytes, frame.innerStart, frame.innerEnd);
  }
  return 'unreadable';
}

export function readNegotiateToken(token: string): NegotiateMechanism {
  try {
    const bytes = decodeBase64(token);
    return bytes === undefined ? 'unreadable' : read(bytes);
  } catch {
    return 'unreadable';
  }
}
