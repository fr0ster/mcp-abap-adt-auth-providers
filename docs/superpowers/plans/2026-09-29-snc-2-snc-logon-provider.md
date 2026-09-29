# SNC logon — step 2: `SncLogonProvider` in auth-providers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `SncLogonProvider` in `@mcp-abap-adt/auth-providers` 4.3.0 — an `IAuthProvider` + `IRfcLogonCredential` that finds the SNC library, checks the SNC product when it can, and hands out the SNC logon parameters that replace `user`/`passwd`.

**Architecture:** The provider only produces parameters; it opens no connection and depends on neither `sap-rfc-lite` nor `@mcp-abap-adt/connection`. Everything that touches the machine goes through one injectable `SncSystem` (environment, file head, registry, process list), so every rule is unit-tested with a fake. Library discovery (`ISncLibraryLocator`) and product checks (`ISncProductProbe`) are strategies with shipped defaults, per this package's rule.

**Tech Stack:** TypeScript (CommonJS, imports without `.js`), Jest via `npm test` (never `npx jest`), Biome; `node:child_process`, `node:fs/promises`, `node:path` only.

**Spec:** `docs/superpowers/specs/2026-09-29-snc-logon-provider-design.md` — sections "2. Provider", "This package's scope", "Testing".

**Prerequisite:** `@mcp-abap-adt/interfaces-auth-sap@1.1.0` published (plan `2026-09-29-snc-1-interfaces-auth-sap.md`). Without it, stop.

## Open questions from the spec, settled here

1. *Can the Secure Login Client report a logged-on profile?* No documented API. `prepare()` checks only that the client runs; a missing certificate surfaces at logon as `A2200019`, which `explainLogonFailure` turns into "log on in the Secure Login Client".
2. *Certificate expiry mid-session.* Same path: a conversation opened after expiry fails with `A2200019` and gets the same explanation. Verified live in the server step, not here.
3. *macOS architecture.* Read the Mach-O header; a universal ("fat") binary — `FAT_MAGIC` or `FAT_MAGIC_64` — is usable when it contains the process's architecture. Linux ELF is read too, so the check is the same everywhere.
4. *`snc_qop` default.* `'9'` — SAP GUI's "Maximum available", measured working. `snc_myname` is sent only when configured.
5. *Server on the broker 2.x API.* Out of this plan; it becomes its own PR before the server step.

## Global Constraints

- The package keeps `"engines": "^22 || ^24 || ^26"` and adds no runtime dependency.
- `@mcp-abap-adt/interfaces-auth-sap` dependency becomes `^1.1.0`.
- Nothing writes to `process.stdout`; diagnostics go to the optional `ILogger` only.
- Errors a caller can act on are `ValidationError` (from `src/errors/TokenProviderErrors.ts`) with `missingFields` where a setting is at fault.
- An explicit `sncLib` is the only candidate and fails loudly; automatic candidates that are missing or of the wrong architecture are skipped with the reason kept.
- The Secure Login Client probe runs only for a library inside the Secure Login Client's installation, decided from the path.
- `rfcLogonParams()` never contains `user` or `passwd`.
- `snc_qop` default `'9'`; valid values exactly `'1'`, `'2'`, `'3'`, `'8'`, `'9'` — SAP defines no other ([SNC parameters](https://help.sap.com/docs/SAP_NETWEAVER_MASTER_DATA_MANAGEMENT/691b78a1277346c995c240dd6ba34f6c/d59ac7ae5b62455393cddd519d9df55a.html)).
- A universal Mach-O comes in two forms: `FAT_MAGIC` `0xcafebabe` with 20-byte `fat_arch` records and `FAT_MAGIC_64` `0xcafebabf` with 32-byte `fat_arch_64` records; both are read, `cputype` first in each record.
- Architecture names are Node's `process.arch` values: `'ia32'`, `'x64'`, `'arm64'`.

## Review Focus

- `SNC_LIB` / `SNC_LIB_64` set to an empty or whitespace string (installers and shells do this) must count as unset, not as a candidate "not found" — test in Task 3.
- `reg.exe` missing, the key absent, or the value absent must skip the registry candidate, never throw out of `locate()` — test in Task 2 (`parseRegQuery` on "not found" output) and Task 3 (registry returns `undefined`).
- Windows paths compare case-insensitively and with either trailing separator — `C:\PROGRAM FILES\SAP\FrontEnd\SecureLogin\lib\sapcrypto.dll` is inside `C:\Program Files\SAP\FrontEnd\SecureLogin\` — test in Task 4.
- The RFC error reaching `explainLogonFailure` may be an `Error`, a string, or the SDK's plain object (`{ name: 'RfcLibError', message: '…A2200019…' }`) — all three must be recognised — test in Task 5.
- A process list that cannot be read must fail `prepare()` with a message saying the check could not run — not claim the client is stopped — test in Task 4.

## File Structure

| File | Responsibility |
|---|---|
| `src/snc/libraryArchitectures.ts` | read a library file's head → the architectures it is built for (PE, Mach-O thin/fat, ELF) |
| `src/snc/SncSystem.ts` | the `SncSystem` seam, its Node implementation, and the output parsers for `reg`, `tasklist`, `ps` |
| `src/snc/secureLoginClient.ts` | Secure Login Client constants: product name, registry key, macOS paths |
| `src/snc/DefaultSncLibraryLocator.ts` | `ISncLibraryLocator` + the default: explicit or automatic discovery |
| `src/snc/SecureLoginClientProbe.ts` | `ISncProductProbe` + the Secure Login Client probe |
| `src/snc/explainSncLogonFailure.ts` | RFC logon error → a message naming cause and fix |
| `src/providers/SncLogonProvider.ts` | the provider: config validation, `prepare()`, the four `IAuthProvider` members, `rfcLogonParams()`, `explainLogonFailure()` |
| `src/__tests__/snc/*.test.ts`, `src/__tests__/snc/fakeSystem.ts` | tests and the fake `SncSystem` |

---

### Task 1: Library architecture reader

**Files:**
- Modify: `package.json` (dependency), `package-lock.json`
- Create: `src/snc/libraryArchitectures.ts`
- Test: `src/__tests__/snc/libraryArchitectures.test.ts`

**Interfaces:**
- Produces: `type SncArch = 'ia32' | 'x64' | 'arm64'`; `libraryArchitectures(head: Buffer): SncArch[]` — empty when the bytes are not a recognised library.

- [ ] **Step 1: Branch and dependency**

```bash
git fetch origin && git checkout -b feat/snc-logon-provider origin/master
npm install @mcp-abap-adt/interfaces-auth-sap@^1.1.0
```

Expected: `package.json` shows `"@mcp-abap-adt/interfaces-auth-sap": "^1.1.0"`.

- [ ] **Step 2: Write the failing test**

`src/__tests__/snc/libraryArchitectures.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { libraryArchitectures } from '../../snc/libraryArchitectures';

function pe(machine: number): Buffer {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(machine, 0x84);
  return b;
}

function machoThin(cputype: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(0xfeedfacf, 0);
  b.writeUInt32LE(cputype, 4);
  return b;
}

// FAT_MAGIC: 20-byte fat_arch records; FAT_MAGIC_64: 32-byte fat_arch_64.
function machoFat(cputypes: number[], wide = false): Buffer {
  const width = wide ? 32 : 20;
  const b = Buffer.alloc(8 + cputypes.length * width);
  b.writeUInt32BE(wide ? 0xcafebabf : 0xcafebabe, 0);
  b.writeUInt32BE(cputypes.length, 4);
  cputypes.forEach((c, i) => b.writeUInt32BE(c, 8 + i * width));
  return b;
}

function elf(machine: number): Buffer {
  const b = Buffer.alloc(64);
  b.writeUInt32BE(0x7f454c46, 0);
  b[5] = 1; // little endian
  b.writeUInt16LE(machine, 0x12);
  return b;
}

describe('libraryArchitectures', () => {
  it.each([
    [0x014c, 'ia32'],
    [0x8664, 'x64'],
    [0xaa64, 'arm64'],
  ])('reads PE machine %s as %s', (machine, arch) => {
    expect(libraryArchitectures(pe(machine))).toEqual([arch]);
  });

  it.each([
    [0x01000007, 'x64'],
    [0x0100000c, 'arm64'],
  ])('reads thin Mach-O cputype %s as %s', (cpu, arch) => {
    expect(libraryArchitectures(machoThin(cpu))).toEqual([arch]);
  });

  it('reads every architecture of a universal Mach-O (FAT_MAGIC)', () => {
    expect(libraryArchitectures(machoFat([0x01000007, 0x0100000c]))).toEqual([
      'x64',
      'arm64',
    ]);
  });

  it('reads every architecture of a 64-bit universal Mach-O (FAT_MAGIC_64)', () => {
    expect(
      libraryArchitectures(machoFat([0x01000007, 0x0100000c], true)),
    ).toEqual(['x64', 'arm64']);
  });

  it('reads a FAT_MAGIC_64 that lacks the process architecture as what it is', () => {
    expect(libraryArchitectures(machoFat([0x00000007], true))).toEqual(['ia32']);
  });

  it.each([
    [0x3e, 'x64'],
    [0xb7, 'arm64'],
  ])('reads ELF machine %s as %s', (machine, arch) => {
    expect(libraryArchitectures(elf(machine))).toEqual([arch]);
  });

  it('returns nothing for bytes that are no library', () => {
    expect(libraryArchitectures(Buffer.from('hello, world'))).toEqual([]);
    expect(libraryArchitectures(Buffer.alloc(0))).toEqual([]);
  });

  it('returns nothing for a PE whose header offset points past the bytes read', () => {
    const b = pe(0x8664);
    b.writeUInt32LE(0x1000, 0x3c);
    expect(libraryArchitectures(b)).toEqual([]);
  });

  it('returns nothing for an unknown PE machine', () => {
    expect(libraryArchitectures(pe(0x01c4))).toEqual([]);
  });
});
```

- [ ] **Step 3: Run to see it fail**

Run: `npm test -- src/__tests__/snc/libraryArchitectures.test.ts`
Expected: FAIL — `Cannot find module '../../snc/libraryArchitectures'`.

- [ ] **Step 4: Implement**

`src/snc/libraryArchitectures.ts`:

```ts
/**
 * Which architectures a shared library is built for, from its first bytes.
 *
 * The RFC SDK loads the SNC library into this process, and a library of the
 * wrong architecture fails there with nothing but `SNCERR_INIT`. The Secure
 * Login Client installer sets the machine-wide `SNC_LIB` to its x86 library,
 * so a 64-bit Node meets exactly that case. Reading the header first turns it
 * into a message naming the file and both architectures.
 */

export type SncArch = 'ia32' | 'x64' | 'arm64';

const PE_MACHINE: Record<number, SncArch> = {
  0x014c: 'ia32',
  0x8664: 'x64',
  0xaa64: 'arm64',
};
const MACHO_CPU: Record<number, SncArch> = {
  0x00000007: 'ia32',
  0x01000007: 'x64',
  0x0100000c: 'arm64',
};
const ELF_MACHINE: Record<number, SncArch> = {
  0x03: 'ia32',
  0x3e: 'x64',
  0xb7: 'arm64',
};

export function libraryArchitectures(head: Buffer): SncArch[] {
  if (head.length >= 0x40 && head.toString('latin1', 0, 2) === 'MZ') {
    const offset = head.readUInt32LE(0x3c);
    if (
      offset + 6 > head.length ||
      head.toString('latin1', offset, offset + 4) !== 'PE\0\0'
    ) {
      return [];
    }
    const arch = PE_MACHINE[head.readUInt16LE(offset + 4)];
    return arch ? [arch] : [];
  }
  if (head.length >= 8) {
    const magicLe = head.readUInt32LE(0);
    if (magicLe === 0xfeedfacf || magicLe === 0xfeedface) {
      const arch = MACHO_CPU[head.readUInt32LE(4)];
      return arch ? [arch] : [];
    }
    const magicBe = head.readUInt32BE(0);
    if (magicBe === 0xcafebabe || magicBe === 0xcafebabf) {
      // FAT_MAGIC: fat_arch is 20 bytes; FAT_MAGIC_64: fat_arch_64 is 32.
      // cputype is the first field of both.
      const width = magicBe === 0xcafebabf ? 32 : 20;
      const count = head.readUInt32BE(4);
      const archs: SncArch[] = [];
      for (let i = 0; i < count && 8 + i * width + 4 <= head.length; i++) {
        const arch = MACHO_CPU[head.readUInt32BE(8 + i * width)];
        if (arch && !archs.includes(arch)) archs.push(arch);
      }
      return archs;
    }
  }
  if (head.length >= 0x14 && head.readUInt32BE(0) === 0x7f454c46) {
    const machine =
      head[5] === 2 ? head.readUInt16BE(0x12) : head.readUInt16LE(0x12);
    const arch = ELF_MACHINE[machine];
    return arch ? [arch] : [];
  }
  return [];
}
```

- [ ] **Step 5: Run to see it pass**

Run: `npm test -- src/__tests__/snc/libraryArchitectures.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json src/snc/libraryArchitectures.ts src/__tests__/snc/libraryArchitectures.test.ts
git commit -m "feat(snc): read a library's architectures from its header"
```

### Task 2: The machine seam — `SncSystem`

**Files:**
- Create: `src/snc/SncSystem.ts`
- Create: `src/snc/secureLoginClient.ts`
- Create: `src/__tests__/snc/fakeSystem.ts`
- Test: `src/__tests__/snc/SncSystem.test.ts`

**Interfaces:**
- Produces:
  - `interface SncSystem { readonly platform: NodeJS.Platform; readonly arch: string; readonly env: Readonly<Record<string, string | undefined>>; readHead(path: string, bytes: number): Promise<Buffer | null>; readRegistryValue(key: string, name: string): Promise<string | undefined>; listProcessNames(): Promise<string[]> }`
  - `nodeSncSystem(): SncSystem`
  - `parseRegQuery(output: string, name: string): string | undefined`, `parseTasklistCsv(output: string): string[]`, `parsePsComm(output: string): string[]` (internal, tested)
  - `SECURE_LOGIN_CLIENT = 'SAP Secure Login Client'`, `SLC_REGISTRY_KEY = 'HKLM\\Software\\SAP\\SecureLogin'`, `MACOS_SLC_APP = '/Applications/Secure Login Client.app/'`, `MACOS_SLC_LIBRARY = '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib'`
  - test helper `fakeSystem(overrides): SncSystem` with `files: Record<string, Buffer>`, `registry: Record<string, string>` keyed `"<key>\\<name>"`, `processes: string[] | Error`

- [ ] **Step 1: Write the failing parser tests**

`src/__tests__/snc/SncSystem.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import {
  parsePsComm,
  parseRegQuery,
  parseTasklistCsv,
} from '../../snc/SncSystem';

describe('parseRegQuery', () => {
  const output = [
    '',
    'HKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin',
    '    InstallPath64    REG_SZ    C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    '',
  ].join('\r\n');

  it('reads the value, spaces in it included', () => {
    expect(parseRegQuery(output, 'InstallPath64')).toBe(
      'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    );
  });

  it('matches the value name case-insensitively', () => {
    expect(parseRegQuery(output, 'installpath64')).toBe(
      'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    );
  });

  it('returns undefined when the value is not in the output', () => {
    expect(parseRegQuery(output, 'InstallPath32')).toBeUndefined();
    expect(
      parseRegQuery(
        'ERROR: The system was unable to find the specified registry key or value.',
        'InstallPath64',
      ),
    ).toBeUndefined();
  });
});

describe('parseTasklistCsv', () => {
  it('takes the image name from each line', () => {
    const output =
      '"System Idle Process","0","Services","0","8 K"\r\n' +
      '"sbus.exe","45952","Console","1","12,345 K"\r\n';
    expect(parseTasklistCsv(output)).toEqual(['System Idle Process', 'sbus.exe']);
  });
});

describe('parsePsComm', () => {
  it('drops the header and blank lines', () => {
    const output =
      'COMM\n/sbin/launchd\n/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client\n\n';
    expect(parsePsComm(output)).toEqual([
      '/sbin/launchd',
      '/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client',
    ]);
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/snc/SncSystem.test.ts`
Expected: FAIL — `Cannot find module '../../snc/SncSystem'`.

- [ ] **Step 3: Implement**

`src/snc/secureLoginClient.ts`:

```ts
/** What this package knows about the SAP Secure Login Client's installation. */

export const SECURE_LOGIN_CLIENT = 'SAP Secure Login Client';

/** Holds `InstallPath64` / `InstallPath32`, each ending in a separator. */
export const SLC_REGISTRY_KEY = 'HKLM\\Software\\SAP\\SecureLogin';

export const MACOS_SLC_APP = '/Applications/Secure Login Client.app/';

export const MACOS_SLC_LIBRARY =
  '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
```

`src/snc/SncSystem.ts`:

```ts
/**
 * Everything SNC discovery asks of the machine, behind one seam.
 *
 * The rules — which library wins, when the Secure Login Client is checked —
 * are the part worth testing, and they only become testable when the
 * environment, the file system, the registry and the process list can be
 * replaced. `nodeSncSystem()` is the real one.
 */

import { execFile } from 'node:child_process';
import { open } from 'node:fs/promises';
import { promisify } from 'node:util';

const run = promisify(execFile);

export interface SncSystem {
  readonly platform: NodeJS.Platform;
  /** `process.arch` — the architecture a library must be built for. */
  readonly arch: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The first `bytes` of a file, or `null` when it cannot be read. */
  readHead(path: string, bytes: number): Promise<Buffer | null>;
  /** A registry value (Windows), or `undefined` when absent or elsewhere. */
  readRegistryValue(key: string, name: string): Promise<string | undefined>;
  /** Running processes' names or paths. Throws when they cannot be listed. */
  listProcessNames(): Promise<string[]>;
}

export function parseRegQuery(output: string, name: string): string | undefined {
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s+(\S.*?)\s+REG_\w+\s+(.*?)\s*$/.exec(line);
    if (match && match[1].toLowerCase() === name.toLowerCase()) {
      return match[2];
    }
  }
  return undefined;
}

export function parseTasklistCsv(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => /^"([^"]*)"/.exec(line)?.[1])
    .filter((name): name is string => Boolean(name));
}

export function parsePsComm(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && line !== 'COMM');
}

export function nodeSncSystem(): SncSystem {
  return {
    platform: process.platform,
    arch: process.arch,
    env: process.env,
    async readHead(path, bytes) {
      try {
        const file = await open(path, 'r');
        try {
          const buffer = Buffer.alloc(bytes);
          const { bytesRead } = await file.read(buffer, 0, bytes, 0);
          return buffer.subarray(0, bytesRead);
        } finally {
          await file.close();
        }
      } catch {
        return null;
      }
    },
    async readRegistryValue(key, name) {
      if (process.platform !== 'win32') return undefined;
      try {
        const { stdout } = await run(
          'reg',
          ['query', key, '/v', name, '/reg:64'],
          { windowsHide: true },
        );
        return parseRegQuery(stdout, name);
      } catch {
        return undefined;
      }
    },
    async listProcessNames() {
      if (process.platform === 'win32') {
        const { stdout } = await run('tasklist', ['/FO', 'CSV', '/NH'], {
          windowsHide: true,
        });
        return parseTasklistCsv(stdout);
      }
      const { stdout } = await run('ps', ['-Ao', 'comm']);
      return parsePsComm(stdout);
    },
  };
}
```

`src/__tests__/snc/fakeSystem.ts`:

```ts
import type { SncSystem } from '../../snc/SncSystem';

export interface FakeSystemOptions {
  platform?: NodeJS.Platform;
  arch?: string;
  env?: Record<string, string | undefined>;
  /** Path → file head. A path not here cannot be read. */
  files?: Record<string, Buffer>;
  /** `"<key>\\<name>"` → value. */
  registry?: Record<string, string>;
  /** The process list, or the error listing it throws. */
  processes?: string[] | Error;
}

export function fakeSystem(options: FakeSystemOptions = {}): SncSystem {
  return {
    platform: options.platform ?? 'win32',
    arch: options.arch ?? 'x64',
    env: options.env ?? {},
    async readHead(path) {
      return options.files?.[path] ?? null;
    },
    async readRegistryValue(key, name) {
      return options.registry?.[`${key}\\${name}`];
    },
    async listProcessNames() {
      if (options.processes instanceof Error) throw options.processes;
      return options.processes ?? [];
    },
  };
}

export function peLibrary(machine: 'ia32' | 'x64'): Buffer {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(machine === 'x64' ? 0x8664 : 0x014c, 0x84);
  return b;
}
```

- [ ] **Step 4: Run to see it pass**

Run: `npm test -- src/__tests__/snc/SncSystem.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/snc/SncSystem.ts src/snc/secureLoginClient.ts src/__tests__/snc
git commit -m "feat(snc): the machine seam and its parsers"
```

### Task 3: Library discovery — `DefaultSncLibraryLocator`

**Files:**
- Create: `src/snc/DefaultSncLibraryLocator.ts`
- Test: `src/__tests__/snc/DefaultSncLibraryLocator.test.ts`

**Interfaces:**
- Consumes: `SncSystem`, `libraryArchitectures`, `SncArch`, `SLC_REGISTRY_KEY`, `MACOS_SLC_LIBRARY`, `ValidationError`.
- Produces: `interface SncLibrary { path: string; archs: SncArch[] }`; `interface ISncLibraryLocator { locate(): Promise<SncLibrary> }`; `class DefaultSncLibraryLocator implements ISncLibraryLocator` with `constructor(system: SncSystem, explicit?: string)`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/DefaultSncLibraryLocator.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { fakeSystem, peLibrary } from './fakeSystem';

const X64_DLL = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const X86_DLL =
  'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32':
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};
const FILES = { [X64_DLL]: peLibrary('x64'), [X86_DLL]: peLibrary('ia32') };

describe('DefaultSncLibraryLocator — explicit sncLib', () => {
  it('returns it when usable', async () => {
    const locator = new DefaultSncLibraryLocator(fakeSystem({ files: FILES }), X64_DLL);
    await expect(locator.locate()).resolves.toEqual({ path: X64_DLL, archs: ['x64'] });
  });

  it('fails on a wrong architecture and tries nothing else', async () => {
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ files: FILES, registry: REGISTRY }),
      X86_DLL,
    );
    const rejected = expect(locator.locate()).rejects.toThrow(
      /built for ia32, this process is x64/,
    );
    await rejected;
    await expect(locator.locate()).rejects.toBeInstanceOf(ValidationError);
  });

  it('fails when the file is missing', async () => {
    const locator = new DefaultSncLibraryLocator(fakeSystem(), 'C:\\nope.dll');
    await expect(locator.locate()).rejects.toThrow(/C:\\nope\.dll: not found/);
  });
});

describe('DefaultSncLibraryLocator — automatic discovery', () => {
  it('the measured mix: no SNC_LIB_64, x86 SNC_LIB, x64 in the registry → the registry library', async () => {
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ env: { SNC_LIB: X86_DLL }, files: FILES, registry: REGISTRY }),
    );
    await expect(locator.locate()).resolves.toEqual({ path: X64_DLL, archs: ['x64'] });
  });

  it('prefers SNC_LIB_64 in a 64-bit process', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({
        env: { SNC_LIB_64: other, SNC_LIB: X86_DLL },
        files: { ...FILES, [other]: peLibrary('x64') },
        registry: REGISTRY,
      }),
    );
    await expect(locator.locate()).resolves.toMatchObject({ path: other });
  });

  it('ignores SNC_LIB_64 in a 32-bit process and takes InstallPath32', async () => {
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ arch: 'ia32', env: { SNC_LIB_64: X64_DLL }, files: FILES, registry: REGISTRY }),
    );
    await expect(locator.locate()).resolves.toEqual({ path: X86_DLL, archs: ['ia32'] });
  });

  it('treats empty or whitespace variables as unset', async () => {
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ env: { SNC_LIB_64: '  ', SNC_LIB: '' }, files: FILES, registry: REGISTRY }),
    );
    await expect(locator.locate()).resolves.toMatchObject({ path: X64_DLL });
  });

  it('skips an absent registry value without failing', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ env: { SNC_LIB: other }, files: { [other]: peLibrary('x64') } }),
    );
    await expect(locator.locate()).resolves.toMatchObject({ path: other });
  });

  it('takes the Secure Login Client default on macOS', async () => {
    const dylib =
      '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
    const macho = Buffer.alloc(32);
    macho.writeUInt32LE(0xfeedfacf, 0);
    macho.writeUInt32LE(0x0100000c, 4);
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ platform: 'darwin', arch: 'arm64', files: { [dylib]: macho } }),
    );
    await expect(locator.locate()).resolves.toEqual({ path: dylib, archs: ['arm64'] });
  });

  it('accepts a 64-bit universal Mach-O (FAT_MAGIC_64) holding the process architecture', async () => {
    const dylib =
      '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
    const fat64 = Buffer.alloc(8 + 2 * 32);
    fat64.writeUInt32BE(0xcafebabf, 0);
    fat64.writeUInt32BE(2, 4);
    fat64.writeUInt32BE(0x01000007, 8); // x64
    fat64.writeUInt32BE(0x0100000c, 8 + 32); // arm64
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ platform: 'darwin', arch: 'arm64', files: { [dylib]: fat64 } }),
    );
    await expect(locator.locate()).resolves.toEqual({
      path: dylib,
      archs: ['x64', 'arm64'],
    });
  });

  it('skips a FAT_MAGIC_64 library that lacks the process architecture, naming what it holds', async () => {
    const dylib =
      '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
    const fat64 = Buffer.alloc(8 + 32);
    fat64.writeUInt32BE(0xcafebabf, 0);
    fat64.writeUInt32BE(1, 4);
    fat64.writeUInt32BE(0x01000007, 8); // x64 only
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ platform: 'darwin', arch: 'arm64', files: { [dylib]: fat64 } }),
    );
    await expect(locator.locate()).rejects.toThrow(
      /built for x64, this process is arm64/,
    );
  });

  it('when nothing is usable, lists every candidate and why', async () => {
    const locator = new DefaultSncLibraryLocator(
      fakeSystem({ env: { SNC_LIB: X86_DLL }, files: { [X86_DLL]: peLibrary('ia32') } }),
    );
    const error = await locator.locate().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).missingFields).toEqual(['sncLib']);
    expect((error as Error).message).toMatch(
      /SNC_LIB .*sapcrypto\.dll: built for ia32, this process is x64/,
    );
  });

  it('when there is no candidate at all, says so', async () => {
    const locator = new DefaultSncLibraryLocator(fakeSystem({ platform: 'linux' }));
    await expect(locator.locate()).rejects.toThrow(/No candidate/);
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/snc/DefaultSncLibraryLocator.test.ts`
Expected: FAIL — `Cannot find module '../../snc/DefaultSncLibraryLocator'`.

- [ ] **Step 3: Implement**

`src/snc/DefaultSncLibraryLocator.ts`:

```ts
/**
 * Where the SNC library is.
 *
 * An explicit `sncLib` is the caller's decision: it is the only candidate, and
 * an unusable one fails naming the path and the reason — nothing is tried
 * behind the caller's back. Without it, candidates are tried in order and an
 * unusable one is skipped with its reason kept: the Secure Login Client
 * installer sets the machine-wide `SNC_LIB` to its x86 library, and that must
 * not hide the x64 one the registry points at.
 */

import { win32 } from 'node:path';
import { ValidationError } from '../errors/TokenProviderErrors';
import { libraryArchitectures, type SncArch } from './libraryArchitectures';
import type { SncSystem } from './SncSystem';
import { MACOS_SLC_LIBRARY, SLC_REGISTRY_KEY } from './secureLoginClient';

export interface SncLibrary {
  path: string;
  archs: SncArch[];
}

export interface ISncLibraryLocator {
  locate(): Promise<SncLibrary>;
}

const HEAD_BYTES = 4096;

interface Candidate {
  source: string;
  path: string;
}

export class DefaultSncLibraryLocator implements ISncLibraryLocator {
  constructor(
    private readonly system: SncSystem,
    private readonly explicit?: string,
  ) {}

  async locate(): Promise<SncLibrary> {
    const explicit = this.explicit?.trim();
    if (explicit) {
      const result = await this.inspect(explicit);
      if ('reason' in result) {
        throw new ValidationError(`sncLib ${explicit}: ${result.reason}`, [
          'sncLib',
        ]);
      }
      return result;
    }

    const skipped: string[] = [];
    for (const candidate of await this.candidates()) {
      const result = await this.inspect(candidate.path);
      if (!('reason' in result)) return result;
      skipped.push(`${candidate.source} ${candidate.path}: ${result.reason}`);
    }
    const detail = skipped.length
      ? ['Tried:', ...skipped.map((line) => `  - ${line}`)]
      : [
          'No candidate: SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found.',
        ];
    throw new ValidationError(
      [
        'No usable SNC library found. Set sncLib to the SNC (GSS) library of your SNC product.',
        ...detail,
      ].join('\n'),
      ['sncLib'],
    );
  }

  private async candidates(): Promise<Candidate[]> {
    const { system } = this;
    const is64 = system.arch === 'x64' || system.arch === 'arm64';
    const variable = (name: string) => system.env[name]?.trim() || undefined;
    const found: Candidate[] = [];

    const lib64 = variable('SNC_LIB_64');
    if (is64 && lib64) found.push({ source: 'SNC_LIB_64', path: lib64 });
    const lib = variable('SNC_LIB');
    if (lib) found.push({ source: 'SNC_LIB', path: lib });

    if (system.platform === 'win32') {
      const name = is64 ? 'InstallPath64' : 'InstallPath32';
      const dir = (
        await system.readRegistryValue(SLC_REGISTRY_KEY, name)
      )?.trim();
      if (dir) {
        found.push({
          source: `registry ${name}`,
          path: win32.join(dir, 'lib', 'sapcrypto.dll'),
        });
      }
    }
    if (system.platform === 'darwin') {
      found.push({
        source: 'Secure Login Client default',
        path: MACOS_SLC_LIBRARY,
      });
    }
    return found;
  }

  private async inspect(
    path: string,
  ): Promise<SncLibrary | { reason: string }> {
    const head = await this.system.readHead(path, HEAD_BYTES);
    if (!head) return { reason: 'not found or not readable' };
    const archs = libraryArchitectures(head);
    if (archs.length === 0) {
      return { reason: 'not a recognised library (PE, Mach-O or ELF)' };
    }
    if (!archs.includes(this.system.arch as SncArch)) {
      return {
        reason: `built for ${archs.join('/')}, this process is ${this.system.arch}`,
      };
    }
    return { path, archs };
  }
}
```

- [ ] **Step 4: Run to see it pass**

Run: `npm test -- src/__tests__/snc/DefaultSncLibraryLocator.test.ts`
Expected: PASS.

- [ ] **Step 5: Prove the skip rule is load-bearing**

In `locate()`, temporarily replace `skipped.push(...)` with `throw new ValidationError(result.reason, ['sncLib']);`. Run the test file; expect "the measured mix" to FAIL. Revert.

- [ ] **Step 6: Commit**

```bash
git add src/snc/DefaultSncLibraryLocator.ts src/__tests__/snc/DefaultSncLibraryLocator.test.ts
git commit -m "feat(snc): find the SNC library — explicit fails loudly, discovery skips the unusable"
```

### Task 4: The Secure Login Client probe

**Files:**
- Create: `src/snc/SecureLoginClientProbe.ts`
- Test: `src/__tests__/snc/SecureLoginClientProbe.test.ts`

**Interfaces:**
- Consumes: `SncSystem`, `SECURE_LOGIN_CLIENT`, `SLC_REGISTRY_KEY`, `MACOS_SLC_APP`, `ValidationError`.
- Produces: `interface ISncProductProbe { readonly product: string; appliesTo(libraryPath: string): Promise<boolean>; check(): Promise<void> }`; `class SecureLoginClientProbe implements ISncProductProbe` with `constructor(system: SncSystem)`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/SecureLoginClientProbe.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { fakeSystem } from './fakeSystem';

const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32':
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};

describe('SecureLoginClientProbe.appliesTo', () => {
  const probe = new SecureLoginClientProbe(fakeSystem({ registry: REGISTRY }));

  it.each([
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\PROGRAM FILES\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
  ])('applies to %s', async (path) => {
    await expect(probe.appliesTo(path)).resolves.toBe(true);
  });

  it.each([
    'C:\\Windows\\System32\\gsskrb5.dll',
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLoginOther\\sapcrypto.dll',
  ])('does not apply to %s', async (path) => {
    await expect(probe.appliesTo(path)).resolves.toBe(false);
  });

  it('applies to nothing when the client is not installed', async () => {
    const bare = new SecureLoginClientProbe(fakeSystem());
    await expect(
      bare.appliesTo('C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll'),
    ).resolves.toBe(false);
  });

  it('applies to the app bundle on macOS', async () => {
    const mac = new SecureLoginClientProbe(fakeSystem({ platform: 'darwin' }));
    await expect(
      mac.appliesTo('/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib'),
    ).resolves.toBe(true);
    await expect(mac.appliesTo('/usr/lib/libgssapi_krb5.dylib')).resolves.toBe(false);
  });
});

describe('SecureLoginClientProbe.check', () => {
  it('passes when sbus.exe runs (any case)', async () => {
    const probe = new SecureLoginClientProbe(fakeSystem({ processes: ['explorer.exe', 'SBUS.EXE'] }));
    await expect(probe.check()).resolves.toBeUndefined();
  });

  it('fails when sbus.exe does not run — sbusagent.exe alone is not the client', async () => {
    const probe = new SecureLoginClientProbe(fakeSystem({ processes: ['sbusagent.exe'] }));
    const error = await probe.check().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as Error).message).toMatch(/Secure Login Client is not running .*sbus\.exe/);
  });

  it('says the check could not run when the process list cannot be read', async () => {
    const probe = new SecureLoginClientProbe(fakeSystem({ processes: new Error('tasklist: access denied') }));
    await expect(probe.check()).rejects.toThrow(
      /Could not check whether the SAP Secure Login Client is running: tasklist: access denied/,
    );
  });

  it('on macOS looks for the app bundle among processes', async () => {
    const running = new SecureLoginClientProbe(
      fakeSystem({
        platform: 'darwin',
        processes: ['/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client'],
      }),
    );
    await expect(running.check()).resolves.toBeUndefined();
    const stopped = new SecureLoginClientProbe(fakeSystem({ platform: 'darwin', processes: ['/sbin/launchd'] }));
    await expect(stopped.check()).rejects.toThrow(/not running/);
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/snc/SecureLoginClientProbe.test.ts`
Expected: FAIL — `Cannot find module '../../snc/SecureLoginClientProbe'`.

- [ ] **Step 3: Implement**

`src/snc/SecureLoginClientProbe.ts`:

```ts
/**
 * Is the SNC product behind a library ready?
 *
 * A probe applies only to libraries it recognises: the Secure Login Client
 * probe to a library inside the client's installation. Any other SNC library
 * — `gsskrb5.dll`, another vendor's — is not probed, so another product is
 * never refused for lacking a process it does not have. The rule reads the
 * library path alone, so a provider built from a destination's settings needs
 * no switch to opt out.
 *
 * It checks that the client runs, not that a profile is logged on: no
 * documented interface says so. A missing certificate surfaces at logon as
 * `A2200019`, which the provider explains.
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
  /** For messages: which product this probe checks. */
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
        (dir) => Boolean(dir?.trim()) && library.startsWith(asDirectory(dir as string)),
      );
    }
    if (system.platform === 'darwin') {
      return libraryPath.startsWith(MACOS_SLC_APP);
    }
    return false;
  }

  async check(): Promise<void> {
    let names: string[];
    try {
      names = await this.system.listProcessNames();
    } catch (error) {
      throw new ValidationError(
        `Could not check whether the ${SECURE_LOGIN_CLIENT} is running: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    const windows = this.system.platform === 'win32';
    const running = windows
      ? names.some((name) => name.toLowerCase() === 'sbus.exe')
      : names.some((name) => name.startsWith(MACOS_SLC_APP));
    if (!running) {
      throw new ValidationError(
        `The ${SECURE_LOGIN_CLIENT} is not running (${
          windows ? 'sbus.exe' : 'Secure Login Client.app'
        } not found). Start it and log on to the profile used for SAP applications.`,
      );
    }
  }
}
```

- [ ] **Step 4: Run to see it pass**

Run: `npm test -- src/__tests__/snc/SecureLoginClientProbe.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/snc/SecureLoginClientProbe.ts src/__tests__/snc/SecureLoginClientProbe.test.ts
git commit -m "feat(snc): probe the Secure Login Client, only for its own library"
```

### Task 5: Explaining a failed SNC logon

**Files:**
- Create: `src/snc/explainSncLogonFailure.ts`
- Test: `src/__tests__/snc/explainSncLogonFailure.test.ts`

**Interfaces:**
- Consumes: `SncLibrary`, `SECURE_LOGIN_CLIENT`.
- Produces: `explainSncLogonFailure(error: unknown, context: { library?: SncLibrary; product?: string }): string | undefined`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/explainSncLogonFailure.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import type { SncLibrary } from '../../snc/DefaultSncLibraryLocator';
import { explainSncLogonFailure } from '../../snc/explainSncLogonFailure';

const library: SncLibrary = {
  path: 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
  archs: ['x64'],
};
const SLC = 'SAP Secure Login Client';

// The SDK's own shape, as measured (sap-rfc-lite RfcLibError).
const noCredential = {
  name: 'RfcLibError',
  code: 1,
  key: 'RFC_COMMUNICATION_FAILURE',
  message:
    '\nLOCATION    CPIC (TCP/IP) with Unicode\nERROR       GSS-API(maj): Miscellaneous failure\n            GSS-API(min): A2200019:Operation aborted by user or\n            application\n',
};

describe('explainSncLogonFailure', () => {
  it.each([
    ['the SDK object', noCredential],
    ['an Error', new Error(`Failed to open RFC connection: ${JSON.stringify(noCredential)}`)],
    ['a string', 'GSS-API(min): A2200019:Operation aborted'],
  ])('recognises A2200019 in %s and names the Secure Login Client', (_, error) => {
    expect(explainSncLogonFailure(error, { library, product: SLC })).toMatch(
      /Log on in the Secure Login Client/,
    );
  });

  it('for another product, names the library instead of the Secure Login Client', () => {
    const message = explainSncLogonFailure(noCredential, {
      library: { path: 'C:\\Windows\\System32\\gsskrb5.dll', archs: ['x64'] },
    });
    expect(message).toMatch(/gsskrb5\.dll/);
    expect(message).not.toMatch(/Secure Login Client/);
  });

  it('recognises SNCERR_INIT and names the library and its architecture', () => {
    const message = explainSncLogonFailure(
      new Error('SNCERR_INIT, Resource problem or gssapi library invalid/missing'),
      { library, product: SLC },
    );
    expect(message).toMatch(/sapcrypto\.dll \(x64\)/);
    expect(message).toMatch(/SNCERR_INIT/);
  });

  it('leaves an unrecognised failure alone', () => {
    expect(
      explainSncLogonFailure(new Error('RFC_LOGON_FAILURE: name or password is incorrect'), {
        library,
        product: SLC,
      }),
    ).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/snc/explainSncLogonFailure.test.ts`
Expected: FAIL — `Cannot find module '../../snc/explainSncLogonFailure'`.

- [ ] **Step 3: Implement**

`src/snc/explainSncLogonFailure.ts`:

```ts
/**
 * What a failed SNC logon means, in words that say what to do.
 *
 * The RFC SDK reports both common failures as a generic communication error;
 * the cause is only in the GSS text. Measured:
 * - `A2200019: Operation aborted by user or application` — the SNC library has
 *   no credential (the Secure Login Client profile is not logged on, or its
 *   certificate expired), and a console process cannot show the prompt.
 * - `SNCERR_INIT … gssapi library invalid/missing` — the SDK could not load
 *   the library it was given.
 */

import type { SncLibrary } from './DefaultSncLibraryLocator';
import { SECURE_LOGIN_CLIENT } from './secureLoginClient';

export interface SncFailureContext {
  library?: SncLibrary;
  /** The product whose probe applied to the library, if any. */
  product?: string;
}

function describe(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

export function explainSncLogonFailure(
  error: unknown,
  context: SncFailureContext,
): string | undefined {
  const text = describe(error);
  const library = context.library
    ? `${context.library.path} (${context.library.archs.join('/')})`
    : 'the SNC library';

  if (/A2200019/.test(text)) {
    return context.product === SECURE_LOGIN_CLIENT
      ? `SNC logon failed: the ${SECURE_LOGIN_CLIENT} has no certificate to present (A2200019). Log on in the Secure Login Client, to the profile used for SAP applications, and connect again.`
      : `SNC logon failed: ${library} has no credential to present (A2200019). Make sure the SNC product behind it is logged on.`;
  }
  if (/SNCERR_INIT|gssapi library invalid\/missing/i.test(text)) {
    return `SNC logon failed: the RFC SDK could not initialise ${library} as its SNC library (SNCERR_INIT).`;
  }
  return undefined;
}
```

- [ ] **Step 4: Run to see it pass**

Run: `npm test -- src/__tests__/snc/explainSncLogonFailure.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/snc/explainSncLogonFailure.ts src/__tests__/snc/explainSncLogonFailure.test.ts
git commit -m "feat(snc): explain the measured SNC logon failures"
```

### Task 6: `SncLogonProvider` and the public surface

**Files:**
- Create: `src/providers/SncLogonProvider.ts`
- Modify: `src/providers/index.ts`, `src/index.ts`
- Test: `src/__tests__/snc/SncLogonProvider.test.ts`, `src/__tests__/exports.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 1–5; `IAuthProvider`, `ICertificateMaterial` from `@mcp-abap-adt/interfaces-auth`; `IRfcLogonCredential` from `@mcp-abap-adt/interfaces-auth-sap`; `ILogger` from `@mcp-abap-adt/interfaces-utils`.
- Produces (public, from the package root): `SncLogonProvider`, `type SncLogonProviderConfig`, `DefaultSncLibraryLocator`, `SecureLoginClientProbe`, `nodeSncSystem`, types `ISncLibraryLocator`, `ISncProductProbe`, `SncLibrary`, `SncSystem`, `SncArch`.

```ts
export interface SncLogonProviderConfig {
  partnerName: string;      // the system's SNC name, e.g. 'p:CN=SID'
  qop?: string;             // '1' | '2' | '3' | '8' | '9', default '9'
  sncLib?: string;          // explicit library; discovered when absent
  myName?: string;          // sent as snc_myname only when set
  system?: SncSystem;       // default nodeSncSystem()
  locator?: ISncLibraryLocator;   // default DefaultSncLibraryLocator(system, sncLib)
  probes?: ISncProductProbe[];    // default [new SecureLoginClientProbe(system)]; [] for none
  logger?: ILogger;
}
```

- [ ] **Step 1: Write the failing provider test**

`src/__tests__/snc/SncLogonProvider.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { SncLogonProvider } from '../../providers/SncLogonProvider';
import { fakeSystem, peLibrary } from './fakeSystem';

const SLC_DLL = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const KRB_DLL = 'C:\\Windows\\System32\\gsskrb5.dll';
const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
};

function slcMachine(processes: string[]) {
  return fakeSystem({
    files: { [SLC_DLL]: peLibrary('x64'), [KRB_DLL]: peLibrary('x64') },
    registry: REGISTRY,
    processes,
  });
}

describe('SncLogonProvider — construction', () => {
  it('requires partnerName', () => {
    const make = () => new SncLogonProvider({ partnerName: '  ', system: slcMachine([]) });
    expect(make).toThrow(ValidationError);
    expect(make).toThrow(/partnerName/);
  });

  it.each(['0', '4', '5', '6', '7', '10', 'max', ''])('refuses qop %p', (qop) => {
    expect(
      () => new SncLogonProvider({ partnerName: 'p:CN=SID', qop, system: slcMachine([]) }),
    ).toThrow(/qop/);
  });

  it.each(['1', '2', '3', '8', '9'])('accepts qop %p', (qop) => {
    expect(
      () => new SncLogonProvider({ partnerName: 'p:CN=SID', qop, system: slcMachine([]) }),
    ).not.toThrow();
  });
});

describe('SncLogonProvider — the IAuthProvider half', () => {
  const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', system: slcMachine(['sbus.exe']) });

  it('is kind snc and contributes no header, cookie or TLS material', async () => {
    expect(provider.kind).toBe('snc');
    await expect(provider.authorizationHeader()).resolves.toBeNull();
    expect(provider.cookies()).toBeNull();
    expect(provider.transportMaterial()).toEqual({});
  });
});

describe('SncLogonProvider — prepare and rfcLogonParams', () => {
  it('refuses rfcLogonParams before prepare', () => {
    const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', system: slcMachine(['sbus.exe']) });
    expect(() => provider.rfcLogonParams()).toThrow(/prepare/);
  });

  it('after prepare: the SNC parameters, default qop 9, and no user or passwd', async () => {
    const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', system: slcMachine(['sbus.exe']) });
    await provider.prepare();
    const params = provider.rfcLogonParams();
    expect(params).toEqual({
      snc_mode: '1',
      snc_partnername: 'p:CN=SID',
      snc_qop: '9',
      snc_lib: SLC_DLL,
    });
    expect(params).not.toHaveProperty('user');
    expect(params).not.toHaveProperty('passwd');
  });

  it('sends snc_myname only when configured', async () => {
    const provider = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      myName: 'p:CN=ME',
      qop: '8',
      system: slcMachine(['sbus.exe']),
    });
    await provider.prepare();
    expect(provider.rfcLogonParams()).toMatchObject({ snc_myname: 'p:CN=ME', snc_qop: '8' });
  });

  it('fails prepare when the Secure Login Client library is found but the client does not run', async () => {
    const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', system: slcMachine([]) });
    await expect(provider.prepare()).rejects.toThrow(/Secure Login Client is not running/);
  });

  it('a non-SLC library with no SLC process: prepare passes, no probe', async () => {
    const provider = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      sncLib: KRB_DLL,
      system: slcMachine([]),
    });
    await provider.prepare();
    expect(provider.rfcLogonParams().snc_lib).toBe(KRB_DLL);
  });

  it('probes: [] turns the product check off', async () => {
    const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', probes: [], system: slcMachine([]) });
    await expect(provider.prepare()).resolves.toBeUndefined();
  });
});

describe('SncLogonProvider — explainLogonFailure', () => {
  it('names the Secure Login Client for its library', async () => {
    const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', system: slcMachine(['sbus.exe']) });
    await provider.prepare();
    expect(provider.explainLogonFailure('GSS-API(min): A2200019')).toMatch(/Secure Login Client/);
  });

  it('does not, for another library', async () => {
    const provider = new SncLogonProvider({ partnerName: 'p:CN=SID', sncLib: KRB_DLL, system: slcMachine([]) });
    await provider.prepare();
    expect(provider.explainLogonFailure('GSS-API(min): A2200019')).not.toMatch(/Secure Login Client/);
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/snc/SncLogonProvider.test.ts`
Expected: FAIL — `Cannot find module '../../providers/SncLogonProvider'`.

- [ ] **Step 3: Implement the provider**

`src/providers/SncLogonProvider.ts`:

```ts
/**
 * Passwordless RFC logon through an installed SNC product.
 *
 * Not a token provider: the SNC library (for the SAP Secure Login Client,
 * `sapcrypto`) authenticates during the RFC logon itself. What this hands out
 * is what replaces `user`/`passwd` — the SNC logon parameters — through
 * `IRfcLogonCredential`, and it takes the credential axis of a connector as
 * an `IAuthProvider` that contributes no header, cookie or TLS material.
 *
 * `prepare()` (run by the connector's `connect()`) finds the library and, when
 * the library belongs to a product with a probe, checks that product runs.
 * It opens no connection and loads no SAP library.
 */

import type {
  IAuthProvider,
  ICertificateMaterial,
} from '@mcp-abap-adt/interfaces-auth';
import type { IRfcLogonCredential } from '@mcp-abap-adt/interfaces-auth-sap';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { ValidationError } from '../errors/TokenProviderErrors';
import {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  type SncLibrary,
} from '../snc/DefaultSncLibraryLocator';
import { explainSncLogonFailure } from '../snc/explainSncLogonFailure';
import {
  type ISncProductProbe,
  SecureLoginClientProbe,
} from '../snc/SecureLoginClientProbe';
import { nodeSncSystem, type SncSystem } from '../snc/SncSystem';

/**
 * SAP's SNC_QOP values: 1 authentication, 2 integrity, 3 privacy, 8 the
 * profile's default, 9 maximum available. No other value is defined, so any
 * other is refused here rather than at the native logon.
 */
const SNC_QOP_VALUES = ['1', '2', '3', '8', '9'];

export interface SncLogonProviderConfig {
  /** The system's SNC name, e.g. `p:CN=SID, O=ACME`. */
  partnerName: string;
  /** Quality of protection `'1' | '2' | '3' | '8' | '9'`; default `'9'` (maximum available). */
  qop?: string;
  /** The SNC library. Only this one is tried when set; discovered otherwise. */
  sncLib?: string;
  /** The user's SNC name; sent as `snc_myname` only when set. */
  myName?: string;
  /** The machine. Default: this one. */
  system?: SncSystem;
  /** Default: `DefaultSncLibraryLocator(system, sncLib)`. */
  locator?: ISncLibraryLocator;
  /** Default: the Secure Login Client probe. `[]` for no product check. */
  probes?: ISncProductProbe[];
  logger?: ILogger;
}

export class SncLogonProvider implements IAuthProvider, IRfcLogonCredential {
  readonly kind = 'snc';

  private readonly partnerName: string;
  private readonly qop: string;
  private readonly myName?: string;
  private readonly locator: ISncLibraryLocator;
  private readonly probes: ISncProductProbe[];
  private readonly logger?: ILogger;

  private library?: SncLibrary;
  private product?: string;

  constructor(config: SncLogonProviderConfig) {
    const partnerName = config.partnerName?.trim();
    if (!partnerName) {
      throw new ValidationError(
        'SncLogonProvider needs partnerName — the system’s SNC name (SAP Logon › connection › Network).',
        ['partnerName'],
      );
    }
    const qop = config.qop ?? '9';
    if (!SNC_QOP_VALUES.includes(qop)) {
      throw new ValidationError(
        `SncLogonProvider: qop must be one of ${SNC_QOP_VALUES.join(', ')} (SAP's SNC_QOP values), got '${qop}'.`,
        ['qop'],
      );
    }
    const system = config.system ?? nodeSncSystem();
    this.partnerName = partnerName;
    this.qop = qop;
    this.myName = config.myName?.trim() || undefined;
    this.locator =
      config.locator ?? new DefaultSncLibraryLocator(system, config.sncLib);
    this.probes = config.probes ?? [new SecureLoginClientProbe(system)];
    this.logger = config.logger;
  }

  async prepare(): Promise<void> {
    const library = await this.locator.locate();
    let product: string | undefined;
    for (const probe of this.probes) {
      if (await probe.appliesTo(library.path)) {
        await probe.check();
        product = probe.product;
        break;
      }
    }
    this.library = library;
    this.product = product;
    this.logger?.debug(
      `SNC library ${library.path} (${library.archs.join('/')})${
        product ? `, ${product} running` : ', no product check'
      }`,
    );
  }

  async authorizationHeader(): Promise<string | null> {
    return null;
  }

  cookies(): string | null {
    return null;
  }

  transportMaterial(): ICertificateMaterial {
    return {};
  }

  rfcLogonParams(): Record<string, string> {
    if (!this.library) {
      throw new Error(
        'SncLogonProvider: not prepared. connect() prepares it; a logon before that has no SNC library.',
      );
    }
    const params: Record<string, string> = {
      snc_mode: '1',
      snc_partnername: this.partnerName,
      snc_qop: this.qop,
      snc_lib: this.library.path,
    };
    if (this.myName) params.snc_myname = this.myName;
    return params;
  }

  explainLogonFailure(error: unknown): string | undefined {
    return explainSncLogonFailure(error, {
      library: this.library,
      product: this.product,
    });
  }
}
```

- [ ] **Step 4: Run to see it pass**

Run: `npm test -- src/__tests__/snc/SncLogonProvider.test.ts`
Expected: PASS.

- [ ] **Step 5: Export and test the surface**

In `src/providers/index.ts` add:

```ts
export {
  SncLogonProvider,
  type SncLogonProviderConfig,
} from './SncLogonProvider';
```

In `src/index.ts`, add `SncLogonProvider` to the `export { … } from './providers'` list and `SncLogonProviderConfig` to the `export type { … } from './providers'` list, then add:

```ts
// SNC logon — an RFC logon credential, not a token provider. The locator and
// the product probes are strategies; bring your own or take these.
export {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  type SncLibrary,
} from './snc/DefaultSncLibraryLocator';
export type { SncArch } from './snc/libraryArchitectures';
export {
  type ISncProductProbe,
  SecureLoginClientProbe,
} from './snc/SecureLoginClientProbe';
export { nodeSncSystem, type SncSystem } from './snc/SncSystem';
```

Append to `src/__tests__/exports.test.ts`:

```ts
describe('public exports — SNC logon', () => {
  it.each([
    'SncLogonProvider',
    'DefaultSncLibraryLocator',
    'SecureLoginClientProbe',
    'nodeSncSystem',
  ])('exports %s', (name) => {
    expect((surface as Record<string, unknown>)[name]).toBeDefined();
  });

  it.each([
    'libraryArchitectures',
    'explainSncLogonFailure',
    'parseRegQuery',
    'parseTasklistCsv',
    'parsePsComm',
  ])('does not export the internal %s', (name) => {
    expect(name in surface).toBe(false);
  });
});
```

- [ ] **Step 6: Full suite and checks**

Run: `npm run lint:check && npm run test:check && npm test`
Expected: PASS (integration suites that need config skip themselves).

- [ ] **Step 7: Prove two rules are load-bearing**

1. In `rfcLogonParams()`, temporarily add `params.user = 'x';` — the "no user or passwd" test must FAIL. Revert.
2. In `prepare()`, temporarily drop the `if (await probe.appliesTo(...))` condition (always `check()`) — "a non-SLC library with no SLC process" must FAIL. Revert.

- [ ] **Step 8: Commit**

```bash
git add src/providers src/index.ts src/__tests__/snc/SncLogonProvider.test.ts src/__tests__/exports.test.ts
git commit -m "feat: SncLogonProvider — SNC logon parameters instead of user/passwd"
```

### Task 7: Documentation and release 4.3.0

**Files:**
- Modify: `CLAUDE.md`, `README.md`, `docs/passwordless-sso.md`, `CHANGELOG.md`, `package.json`, `package-lock.json`

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces: `@mcp-abap-adt/auth-providers@4.3.0` — what the broker and server steps depend on.

- [ ] **Step 1: `CLAUDE.md`** — in "Project Overview", add after the `UaaPasscodeProvider` bullet:

```markdown
- **`SncLogonProvider`** — not a token provider: an `IAuthProvider` + `IRfcLogonCredential` whose `rfcLogonParams()` replace `user`/`passwd` in an RFC logon, through an installed SNC product (SAP Secure Login Client). `src/snc/` holds its strategies: library discovery and product probes, behind the `SncSystem` machine seam.
```

In "Package responsibilities", change "This package ONLY: - implements `ITokenProvider`" to "- implements `ITokenProvider`, and one RFC logon credential (`SncLogonProvider`)", and add to "does NOT": "- open connections or load SAP libraries — `SncLogonProvider` only produces logon parameters; the RFC wire is `@mcp-abap-adt/connection`'s". Replace the `docs/passwordless-sso.md` sentence "nothing in it is built yet" with "SNC over RFC is built (`SncLogonProvider`); the HTTP mechanisms are not".

- [ ] **Step 2: `README.md`** — add a section "Passwordless RFC logon (SNC)": prerequisites (NW RFC SDK and `@mcp-abap-adt/sap-rfc-lite` for the connection, an SNC product such as the SAP Secure Login Client, installed and logged on), the config table from `SncLogonProviderConfig`, library discovery order (explicit → `SNC_LIB_64` (64-bit) → `SNC_LIB` → registry `InstallPath64/32` → macOS default; unusable automatic candidates skipped), the probe rule, and the two explained failures (`A2200019`, `SNCERR_INIT`). Example:

```ts
const credential = new SncLogonProvider({ partnerName: 'p:CN=SID' });
new AdtOnPremConnector(
  config,
  credential,
  new RfcTransport(rfcConversationFrom(config, () => credential.rfcLogonParams()), logger),
  logger,
);
```

with a note that the `logon` argument arrives in `@mcp-abap-adt/connection` step 3.

- [ ] **Step 3: `docs/passwordless-sso.md`** — in "Summary" and "Where each applies", mark SNC through Secure Login as **Measured** 2026-09-29 (on-prem, Windows, SLC 3.0.3, SLS certificate: logon, discovery, reads, LOCK/UNLOCK). In "From Node.js", replace the `node-rfc` bullet's conclusion with `@mcp-abap-adt/sap-rfc-lite` + `SncLogonProvider`. In "Options for this package", replace "Rejected — an RFC/SNC transport" with "**Built — `SncLogonProvider`**: the credential half of SNC over RFC; the transport stays in `@mcp-abap-adt/connection`". Answer open question 2 partly: the Secure Login Client enrols over a plain HTTP API (`/api/v1/getProfiles`, `/api/v1/getCertificateTemplateStandardBrowser`, `/slc/v1/login`) — Measured, from its profile registry; not used by this package.

- [ ] **Step 4: `CHANGELOG.md`** under `## [Unreleased]`:

```markdown
### Added

- **`SncLogonProvider`** — passwordless RFC logon through an installed SNC
  product such as the SAP Secure Login Client. An `IAuthProvider` +
  `IRfcLogonCredential` (`@mcp-abap-adt/interfaces-auth-sap` 1.1.0): no
  header, cookie or TLS material; `rfcLogonParams()` gives `snc_mode`,
  `snc_partnername`, `snc_qop` (default 9), `snc_lib` and optionally
  `snc_myname` in place of `user`/`passwd`. `prepare()` finds the SNC library
  — an explicit `sncLib` only, or `SNC_LIB_64` / `SNC_LIB` / the Secure Login
  Client's registry entry / its macOS bundle, skipping a candidate that is
  missing or of the wrong architecture (the installer's machine-wide
  `SNC_LIB` is the x86 library) — and checks the Secure Login Client runs when
  the library is its own. `explainLogonFailure()` turns `A2200019` and
  `SNCERR_INIT` into what to do. Strategies: `DefaultSncLibraryLocator`,
  `SecureLoginClientProbe`, `nodeSncSystem`.

### Changed

- **`@mcp-abap-adt/interfaces-auth-sap` `^1.1.0`.**
```

- [ ] **Step 5: Version and verify** — `"version": "4.3.0"`, CHANGELOG `## [4.3.0] - <date>` with a fresh `## [Unreleased]` above, `npm install --package-lock-only`, then `npm run build && npm run lint:check && npm test`. Expected: PASS.

- [ ] **Step 6: Commit and PR**

```bash
git add CLAUDE.md README.md docs/passwordless-sso.md CHANGELOG.md package.json package-lock.json
git commit -m "chore(release): 4.3.0 — SncLogonProvider, passwordless RFC logon over SNC"
```

Push, open the PR, merge after review; publish through the repo's release flow. The spec stays in `docs/superpowers/specs/` until steps 3–5 are done too.

### Task 8: Live check on a real system (manual, not CI)

**Files:** none committed here.

- [ ] **Step 1:** On a Windows machine with the NW RFC SDK, `@mcp-abap-adt/sap-rfc-lite`, and the Secure Login Client logged on, run a scratch script: `new SncLogonProvider({ partnerName: '<system SNC name>' })`, `await prepare()`, print `rfcLogonParams()` — expect the registry's x64 `sapcrypto.dll` even with the installer's x86 `SNC_LIB` set.
- [ ] **Step 2:** Feed those params into the hand-built conversation factory of the private probe (the same one that passed on 2026-09-29) in place of its own `snc_*` values; expect discovery 200 and LOCK/UNLOCK 200.
- [ ] **Step 3:** Log the Secure Login Client profile out, run again; expect the RFC open to fail and `explainLogonFailure(error)` to say "Log on in the Secure Login Client". Record the three results in the PR.
