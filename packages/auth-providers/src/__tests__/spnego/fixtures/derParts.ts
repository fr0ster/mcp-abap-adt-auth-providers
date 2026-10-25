// DER parts for building Negotiate tokens in tests (RFC 2743 §3.1, RFC 4178 §4.2).
// Kerberos tokens built here are stand-ins until real captured ones replace them.

export function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}

export function tlv(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
}

export const OID_KRB5 = Buffer.from([
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
]);
export const OID_KRB5_MS = Buffer.from([
  0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
]);
export const OID_NTLM = Buffer.from([
  0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
]);
export const OID_SPNEGO = Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);

export const NTLM_NEGOTIATE = Buffer.concat([
  Buffer.from('NTLMSSP\0', 'latin1'),
  Buffer.from([1, 0, 0, 0, 0x07, 0x82, 0x08, 0xa2]),
]);

// GSS framing: 0x60, length, OID, tok_id 01 00 (AP-REQ), then a body.
export function gssKerberos(oid: Buffer = OID_KRB5, body = 64): Buffer {
  return tlv(
    0x60,
    tlv(0x06, oid),
    Buffer.from([0x01, 0x00]),
    Buffer.alloc(body, 0x6e),
  );
}

export interface InitParts {
  mechs: Buffer[];
  mechToken?: Buffer | undefined;
  reqFlags?: boolean;
  mic?: boolean;
}

export function negTokenInit(p: InitParts): Buffer {
  const mechTypes = tlv(0xa0, tlv(0x30, ...p.mechs.map((o) => tlv(0x06, o))));
  const items = [mechTypes];
  if (p.reqFlags) items.push(tlv(0xa1, tlv(0x03, Buffer.from([0x00, 0x40]))));
  if (p.mechToken) items.push(tlv(0xa2, tlv(0x04, p.mechToken)));
  if (p.mic) items.push(tlv(0xa3, tlv(0x04, Buffer.from('mic'))));
  return tlv(0x60, tlv(0x06, OID_SPNEGO), tlv(0xa0, tlv(0x30, ...items)));
}

export const b64 = (b: Buffer): string => b.toString('base64');
