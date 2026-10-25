import { readNegotiateToken } from '../../spnego/negotiateToken';
import { CAPTURED_KERBEROS, CAPTURED_SPNEGO } from './fixtures/capturedTokens';
import {
  b64,
  gssKerberos,
  NTLM_NEGOTIATE,
  negTokenInit,
  OID_KRB5,
  OID_KRB5_MS,
  OID_NTLM,
  OID_SPNEGO,
  tlv,
} from './fixtures/derParts';

// The Kerberos tokens are the ones captured on the Kerberos stand (MIT krb5);
// the legacy Microsoft OID, which MIT does not produce, and NTLM are built.
const KERBEROS = Buffer.from(CAPTURED_KERBEROS, 'base64');
const SPNEGO = Buffer.from(CAPTURED_SPNEGO, 'base64');

describe('readNegotiateToken', () => {
  describe('kerberos', () => {
    it('a captured GSS-framed Kerberos token (mechanism kerberos)', () => {
      // Its frame has a two-byte length: 0x60 0x82 <hi> <lo>.
      expect(KERBEROS[0]).toBe(0x60);
      expect(KERBEROS[1]).toBe(0x82);
      expect(readNegotiateToken(CAPTURED_KERBEROS)).toBe('kerberos');
    });
    it('a captured SPNEGO NegTokenInit (mechanism spnego)', () => {
      expect(SPNEGO.subarray(4, 12).equals(tlv(0x06, OID_SPNEGO))).toBe(true);
      expect(readNegotiateToken(CAPTURED_SPNEGO)).toBe('kerberos');
    });
    it('a SPNEGO NegTokenInit built around the captured Kerberos token', () => {
      const t = negTokenInit({
        mechs: [OID_KRB5, OID_NTLM],
        mechToken: KERBEROS,
        reqFlags: true,
      });
      expect(readNegotiateToken(b64(t))).toBe('kerberos');
    });
    it('a SPNEGO NegTokenInit with the legacy Microsoft OID first', () => {
      const t = negTokenInit({
        mechs: [OID_KRB5_MS, OID_KRB5],
        mechToken: gssKerberos(OID_KRB5_MS),
        mic: true,
      });
      expect(readNegotiateToken(b64(t))).toBe('kerberos');
    });
    it('a SPNEGO token whose first mechanism is Kerberos but whose token is not GSS Kerberos is unreadable', () => {
      const t = negTokenInit({
        mechs: [OID_KRB5],
        mechToken: Buffer.from('garbage-token'),
      });
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });
    it('a raw GSS frame with the legacy Microsoft OID is unreadable', () => {
      expect(readNegotiateToken(b64(gssKerberos(OID_KRB5_MS)))).toBe(
        'unreadable',
      );
    });
    it('NegTokenInit fields: unknown tag, repeated or out of order', () => {
      const types = tlv(0xa0, tlv(0x30, tlv(0x06, OID_KRB5)));
      const flags = tlv(0xa1, tlv(0x03, Buffer.from([0x00, 0x40])));
      const tok = tlv(0xa2, tlv(0x04, KERBEROS));
      const mic = tlv(0xa3, tlv(0x04, Buffer.from('mic')));
      const init = (...f: Buffer[]) =>
        b64(
          tlv(0x60, tlv(0x06, OID_SPNEGO), tlv(0xa0, tlv(0x30, types, ...f))),
        );
      expect(readNegotiateToken(init(flags, tok, mic))).toBe('kerberos');
      expect(readNegotiateToken(init(tok, tlv(0xa4, Buffer.from([0]))))).toBe(
        'unreadable',
      );
      expect(readNegotiateToken(init(flags, flags, tok))).toBe('unreadable');
      expect(readNegotiateToken(init(tok, flags))).toBe('unreadable');
      expect(readNegotiateToken(init(tok, tok))).toBe('unreadable');
    });
    it('a SPNEGO token with Kerberos listed second is unreadable', () => {
      const t = negTokenInit({
        mechs: [OID_NTLM, OID_KRB5],
        mechToken: KERBEROS,
      });
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });
    it('a SPNEGO token with no mechanism token is unreadable', () => {
      expect(readNegotiateToken(b64(negTokenInit({ mechs: [OID_KRB5] })))).toBe(
        'unreadable',
      );
    });
  });

  describe('ntlm', () => {
    it('a raw NTLM message', () => {
      expect(readNegotiateToken(b64(NTLM_NEGOTIATE))).toBe('ntlm');
      expect(readNegotiateToken('TlRMTVNTUAAB')).toBe('ntlm');
    });
    it('NTLM as the mechanism token inside a NegTokenInit', () => {
      const t = negTokenInit({
        mechs: [OID_NTLM],
        mechToken: NTLM_NEGOTIATE,
      });
      expect(readNegotiateToken(b64(t))).toBe('ntlm');
    });
    it('NTLM inside a NegTokenInit that lists Kerberos first', () => {
      const t = negTokenInit({
        mechs: [OID_KRB5, OID_NTLM],
        mechToken: NTLM_NEGOTIATE,
      });
      expect(readNegotiateToken(b64(t))).toBe('ntlm');
    });
  });

  describe('unreadable', () => {
    it.each([
      ['empty', ''],
      ['not base64', 'not base64!!'],
      ['whitespace inside', 'TlRM TVNT'],
      ['bad padding', 'TlRMTVNTUAAB='],
      ['padding in the middle', 'TlRM=VNTUAAB'],
      ['url-safe alphabet', 'TlRMTVNTUA-_'],
      ['one byte', 'YQ=='],
    ])('%s', (_n, s) => {
      expect(readNegotiateToken(s)).toBe('unreadable');
    });

    it('random bytes', () => {
      for (let i = 1; i < 64; i++) {
        const b = Buffer.alloc(i);
        for (let j = 0; j < i; j++) b[j] = (j * 131 + i * 17 + 7) & 0xff;
        b[0] = 0x61; // never the GSS tag or NTLMSSP
        expect(readNegotiateToken(b64(b))).toBe('unreadable');
      }
    });

    it('seeded random bodies behind a correct 0x60 frame', () => {
      let x = 12345;
      const next = () => {
        x = (Math.imul(x, 1103515245) + 12345) >>> 0;
        return x >>> 24;
      };
      for (let i = 0; i < 300; i++) {
        const body = Buffer.alloc(1 + (i % 120));
        for (let j = 0; j < body.length; j++) body[j] = next();
        expect(readNegotiateToken(b64(tlv(0x60, body)))).toBe('unreadable');
      }
    });

    it('a GSS length past the end of the buffer', () => {
      const t = Buffer.from(KERBEROS);
      const length = (((t[2] ?? 0) << 8) | (t[3] ?? 0)) + 1;
      t[2] = length >> 8;
      t[3] = length & 0xff;
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('a length field of five bytes', () => {
      const body = Buffer.concat([
        tlv(0x06, OID_KRB5),
        Buffer.from([1, 0]),
        Buffer.alloc(8),
      ]);
      const t = Buffer.concat([
        Buffer.from([0x60, 0x85, 0, 0, 0, 0, body.length]),
        body,
      ]);
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('an indefinite length', () => {
      const body = Buffer.concat([
        tlv(0x06, OID_KRB5),
        Buffer.from([1, 0]),
        Buffer.alloc(8),
      ]);
      const t = Buffer.concat([
        Buffer.from([0x60, 0x80]),
        body,
        Buffer.from([0, 0]),
      ]);
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('an indefinite length inside a NegTokenInit', () => {
      // The captured token: 60 82 LL LL, the SPNEGO OID (8 bytes),
      // a0 82 LL LL, then the NegTokenInit SEQUENCE at 16.
      const t = Buffer.from(SPNEGO);
      expect(t[12]).toBe(0xa0);
      expect(t[16]).toBe(0x30);
      t[17] = 0x80;
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('trailing bytes after the framed token', () => {
      const t = Buffer.concat([KERBEROS, Buffer.from([0])]);
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('a mechanism token longer than its container', () => {
      const t = Buffer.from(
        negTokenInit({ mechs: [OID_KRB5], mechToken: KERBEROS }),
      );
      // the OCTET STRING of the mechToken, 04 82 <hi> <lo>, right before it:
      // inflate its length past what remains
      const at = t.indexOf(KERBEROS);
      expect(t[at - 4]).toBe(0x04);
      expect(t[at - 3]).toBe(0x82);
      t[at - 2] = 0x7f;
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('a NegTokenResp (not an init)', () => {
      const t = tlv(0xa1, tlv(0x30, tlv(0xa0, tlv(0x0a, Buffer.from([1])))));
      expect(readNegotiateToken(b64(t))).toBe('unreadable');
    });

    it('a deeply nested structure does not recurse', () => {
      let t: Buffer = Buffer.from([0x05, 0x00]);
      for (let i = 0; i < 2000; i++) t = tlv(0x30, t);
      expect(readNegotiateToken(b64(tlv(0x60, tlv(0xa0, t))))).toBe(
        'unreadable',
      );
    });

    const valid: Array<[string, Buffer]> = [
      ['captured GSS Kerberos', KERBEROS],
      ['captured SPNEGO', SPNEGO],
      [
        'NegTokenInit Kerberos',
        negTokenInit({
          mechs: [OID_KRB5, OID_NTLM],
          mechToken: KERBEROS,
          reqFlags: true,
          mic: true,
        }),
      ],
      [
        'NegTokenInit NTLM',
        negTokenInit({ mechs: [OID_NTLM], mechToken: NTLM_NEGOTIATE }),
      ],
    ];
    it.each(valid)('every truncation of %s', (_n, t) => {
      for (let n = 0; n < t.length; n++) {
        expect(readNegotiateToken(b64(t.subarray(0, n)))).toBe('unreadable');
      }
    });

    it('every truncation of a raw NTLM message below its signature', () => {
      for (let n = 0; n < 8; n++) {
        expect(readNegotiateToken(b64(NTLM_NEGOTIATE.subarray(0, n)))).toBe(
          'unreadable',
        );
      }
    });

    it('never throws on a non-string', () => {
      expect(readNegotiateToken(undefined as unknown as string)).toBe(
        'unreadable',
      );
      expect(readNegotiateToken(42 as unknown as string)).toBe('unreadable');
    });

    it('a large input with a huge length is unreadable', () => {
      const big = Buffer.concat([
        Buffer.from([0x60, 0x84, 0x04, 0x00, 0x00, 0x00]),
        Buffer.alloc(1 << 20, 0x30),
      ]);
      expect(readNegotiateToken(b64(big))).toBe('unreadable');
    });
  });
});
