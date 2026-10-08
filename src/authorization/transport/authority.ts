/**
 * Which `Host` a listener answers for (spec §6a1, §6d.3.5): the header is
 * read through the WHATWG URL host parser — anyone's text, so the
 * platform's parser decides what host it names, never a regex — and a
 * loopback name counts only from a loopback peer.
 */

/**
 * An authority (`host` or `host:port`) in canonical form: the hostname as
 * the WHATWG URL host parser gives it (lowercased, `127.1` → `127.0.0.1`,
 * `[0:0:0:0:0:0:0:1]` → `[::1]`, IDNA applied), one trailing dot dropped.
 */
export interface Authority {
  readonly host: string;
  /** `undefined` when the text named no port. */
  readonly port: number | undefined;
  /** `localhost`, `127.0.0.0/8`, `[::1]` or `[::ffff:127.x.y.z]`. */
  readonly loopback: boolean;
  /** `0.0.0.0` or `[::]`: a bind address, never an authority. */
  readonly unspecified: boolean;
}

/** Characters that make a text more than an authority. */
const NOT_AUTHORITY = new Set(['@', '/', '\\', '?', '#']);

/**
 * Reads `host[:port]` through the WHATWG URL host parser. `undefined` for
 * anything that is not exactly an authority: userinfo, a path, a query or
 * fragment, whitespace, an empty or out-of-range port, a host the parser
 * refuses.
 */
export function parseAuthority(value: unknown): Authority | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  for (const character of value) {
    if (NOT_AUTHORITY.has(character) || character.trim() === '') {
      return undefined;
    }
  }
  let url: URL;
  try {
    url = new URL(`http://${value}`);
  } catch {
    return undefined;
  }
  if (url.pathname !== '/' || url.username !== '' || url.password !== '') {
    return undefined;
  }
  // Whether the text named a port: a `:` after the host (after `]` for a
  // bracketed IPv6 address). The parser turns `:80` into no port at all.
  const close = value.lastIndexOf(']');
  const named = value.indexOf(':', close < 0 ? 0 : close) >= 0;
  if (named && value.endsWith(':')) return undefined;
  const port = named ? Number(url.port === '' ? 80 : url.port) : undefined;
  const host = url.hostname.endsWith('.')
    ? url.hostname.slice(0, -1)
    : url.hostname;
  if (host === '') return undefined;
  return {
    host,
    port,
    loopback: loopbackHost(host),
    unspecified: host === '0.0.0.0' || host === '[::]',
  };
}

/**
 * Whether a canonical hostname is loopback: `localhost`, an IPv4 address in
 * `127.0.0.0/8`, `[::1]`, or an IPv4-mapped `[::ffff:7fXX:XXXX]` (the
 * parser's form of `::ffff:127.x.y.z`).
 */
function loopbackHost(host: string): boolean {
  if (host === 'localhost' || host === '[::1]') return true;
  if (isLoopbackPeer(host)) return true;
  const mapped = '[::ffff:';
  if (!host.startsWith(mapped) || !host.endsWith(']')) return false;
  const groups = host.slice(mapped.length, -1).split(':');
  const high = groups[0];
  return (
    groups.length === 2 &&
    high !== undefined &&
    high.length === 4 &&
    high.startsWith('7f')
  );
}

/**
 * Whether a peer address is loopback: `127.0.0.0/8`, `::1`, or an
 * IPv4-mapped `::ffff:127.x.y.z`. Plain code over the dotted quad.
 */
export function isLoopbackPeer(address: unknown): boolean {
  if (typeof address !== 'string') return false;
  if (address === '::1') return true;
  const mapped = address.startsWith('::ffff:');
  const v4 = mapped ? address.slice('::ffff:'.length) : address;
  const parts = v4.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (part === '' || part.length > 3) return false;
    for (const digit of part) if (digit < '0' || digit > '9') return false;
    if (Number(part) > 255) return false;
  }
  return parts[0] === '127';
}

/**
 * Whether a loopback listener answers a request (spec §6a1): its `Host`
 * names a loopback authority (any spelling the URL parser reads as one)
 * with the bound port — a `Host` without a port is port 80, as HTTP has it
 * — and its peer is loopback. A machine on the network sending
 * `Host: localhost` is not this machine's browser.
 */
export function answersLoopback(
  hostHeader: unknown,
  peer: unknown,
  boundPort: number,
): boolean {
  const asked = parseAuthority(hostHeader);
  if (!asked?.loopback) return false;
  return isLoopbackPeer(peer) && (asked.port ?? 80) === boundPort;
}
