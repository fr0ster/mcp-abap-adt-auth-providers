#!/usr/bin/env node
/**
 * The README's refusal tables (spec §11.4), generated: every word comes from
 * auth-errors' `render`, every row set from the allowlists of interfaces-auth
 * as auth-errors sees it — nothing here copies a sentence. A table that
 * meets a value it has no row text for throws, so a new problem or verdict
 * cannot be left out silently.
 *
 *   node scripts/generate-refusal-tables.mjs          # rewrite README.md
 *   node scripts/generate-refusal-tables.mjs --check  # exit 1 when it differs
 *   … --readme <path>                                  # another file (tests)
 *
 * Each table lives between `<!-- generated:refusal-table NAME -->` and
 * `<!-- /generated:refusal-table NAME -->`. Tasks 18–26 regenerate the rows
 * of the refusals they change; Task 30 rewrites the prose around them.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { render } = require('@mcp-abap-adt/auth-errors');
// interfaces-auth as auth-errors resolves it: the 6.0.0 allowlists.
const contract = createRequire(require.resolve('@mcp-abap-adt/auth-errors'))(
  '@mcp-abap-adt/interfaces-auth',
);

const readmeArg = process.argv.indexOf('--readme');
const README =
  readmeArg > 0 && process.argv[readmeArg + 1] !== undefined
    ? process.argv[readmeArg + 1]
    : join(dirname(fileURLToPath(import.meta.url)), '..', 'README.md');

const quoted = (text) => `"${text}"`;
const cell = (text) => text.replaceAll('|', '\\|');

/** The row text for each value of an allowlist; a value without one throws. */
function each(values, rows, table) {
  return values.map((value) => {
    if (!Object.hasOwn(rows, value)) {
      throw new Error(`${table}: no row for ${JSON.stringify(value)}`);
    }
    return [value, rows[value]];
  });
}

/** "What `rejected()` answers": the verdicts of `system-refused` (B1–B6). */
function rejectedTable() {
  const own = [
    ['Basic', 'user-password'],
    ['certificate', 'client-certificate'],
    ['SAML cookies', 'saml-session'],
    ['fixed token', 'token'],
  ]
    .map(
      ([provider, credential]) =>
        `${provider} ${quoted(render('credential-refused', { credential, at: 'request' }).reason)}`,
    )
    .join('; ');
  const examples = {
    'not-authorized': { rejection: '`403`', facts: { status: 403 } },
    redirected: { rejection: '`3xx`, e.g. `302`', facts: { status: 302 } },
    'system-failed': { rejection: '`5xx`, e.g. `503`', facts: { status: 503 } },
    'other-status': {
      rejection: 'any other status, e.g. `404`',
      facts: { status: 404 },
    },
    'rfc-failure': {
      rejection: 'another RFC key, e.g. `RFC_COMMUNICATION_FAILURE`',
      facts: { rfcKey: 'RFC_COMMUNICATION_FAILURE' },
    },
    unknown: { rejection: 'neither a status nor a known key', facts: {} },
  };
  const lines = [
    '| The rejection | Kind | Basic, certificate, SAML cookies, fixed token | Token providers, `TokenAuthProvider.from` |',
    '|---|---|---|---|',
    `| \`401\`, \`RFC_LOGON_FAILURE\` | \`credential-refused\` | their own refusal: ${cell(own)} | one renewal; Ok only if the credential changed |`,
  ];
  for (const [verdict, example] of each(
    contract.SYSTEM_REFUSED_VERDICTS,
    examples,
    'rejected',
  )) {
    const logon = render('system-refused', {
      verdict,
      ...example.facts,
      at: 'logon',
    });
    const request = render('system-refused', {
      verdict,
      ...example.facts,
      at: 'request',
    });
    const words =
      logon.reason === request.reason
        ? quoted(logon.reason)
        : `at a logon ${quoted(logon.reason)}; at a request ${quoted(request.reason)}`;
    const hint = logon.hint === undefined ? '' : ` — ${quoted(logon.hint)}`;
    const tokens =
      verdict === 'unknown'
        ? 'one renewal — the rejection cannot tell'
        : 'the same, no renewal';
    lines.push(
      `| ${example.rejection} | \`system-refused\` \`${verdict}\` | ${cell(words + hint)} | ${tokens} |`,
    );
  }
  return lines.join('\n');
}

/** "Refusals": client certificate, client authentication, binding, TLS. */
function refusalsTable() {
  const lines = ['| When | Kind | Reason | Hint |', '|---|---|---|---|'];
  const row = (when, kind, words) =>
    lines.push(
      `| ${when} | ${kind} | ${cell(words.reason)} | ${cell(words.hint ?? '')} |`,
    );
  for (const [problem, when] of each(
    contract.CLIENT_CERTIFICATE_PROBLEMS,
    {
      incomplete: 'material without a PFX or without both certificate and key',
      unusable: 'material no TLS context accepts',
      expired:
        'a client certificate past its `notAfter`, when pinned or before a request or logon presents it',
    },
    'refusals',
  )) {
    row(
      when,
      `\`client-certificate\` \`${problem}\``,
      render('client-certificate', { problem }),
    );
  }
  for (const [problem, when] of each(
    contract.CLIENT_AUTHENTICATION_PROBLEMS,
    {
      'signing-key-unusable':
        'a signing key that is not a private key of the algorithm',
      'result-unsendable': "a strategy's result that cannot be sent",
      'basic-client-id-colon':
        "raw `clientSecretBasic` with a client id containing ':'",
    },
    'refusals',
  )) {
    row(
      when,
      `\`client-authentication\` \`${problem}\``,
      render('client-authentication', { problem }),
    );
  }
  for (const [problem, when] of each(
    contract.TOKEN_BINDING_PROBLEMS,
    {
      'bound-to-unpinned': 'a bound token held, and no certificate pinned',
      'renewed-bound-elsewhere':
        'a token renewed because it was bound to another certificate, and the new one is bound elsewhere too',
    },
    'refusals',
  )) {
    row(
      when,
      `\`token-binding\` \`${problem}\``,
      render('token-binding', { problem }),
    );
  }
  // TLS: one row per set of words, every code that renders them listed.
  const lead = render('unknown', { operation: 'token-request' }).reason.replace(
    / \(unknown error\)$/,
    '',
  );
  const groups = new Map();
  for (const code of contract.TLS_FAILURE_CODES) {
    const words = render('tls', { operation: 'token-request', code });
    const prefix = `${lead}: `;
    const suffix = ` (${code})`;
    if (!words.reason.startsWith(prefix) || !words.reason.endsWith(suffix)) {
      throw new Error(`refusals: unexpected tls words for ${code}`);
    }
    const says = words.reason.slice(prefix.length, -suffix.length);
    const key = `${says}\u0000${words.hint ?? ''}`;
    const group = groups.get(key) ?? { says, hint: words.hint, codes: [] };
    group.codes.push(code);
    groups.set(key, group);
  }
  for (const { says, hint, codes } of groups.values()) {
    row(
      `a TLS failure: ${codes.map((c) => `\`${c}\``).join(', ')}`,
      '`tls`',
      { reason: `\`<operation>\` failed: ${says} (\`<code>\`)`, hint },
    );
  }
  return lines.join('\n');
}

/** The quoted prefix every `saml-assertion` reason starts with. */
const samlPrefix = (check) => `the SAML assertion was refused (${check}): `;

/**
 * A rule's words with a count of two shown as `<n>`: rendered with and
 * without the count, so only a rule whose words name it is rewritten.
 */
function samlRuleWords(rule, check) {
  const plain = render('saml-assertion', { rule, check }).reason;
  const counted = render('saml-assertion', { rule, check, count: 2 }).reason;
  const words = counted === plain ? plain : counted.replace(' 2 ', ' <n> ');
  const prefix = samlPrefix(check);
  if (!words.startsWith(prefix)) {
    throw new Error(`saml: unexpected words for ${rule}`);
  }
  return words.slice(prefix.length);
}

/**
 * "Refusal messages": every rule of Appendix B (spec), in the allowlist's
 * order — its check, its words after the common prefix, and the one
 * diagnostic it may carry.
 */
function samlTable() {
  const lines = [
    '| `check` | `rule` | Words, after `the SAML assertion was refused (<check>): ` | Diagnostic |',
    '|---|---|---|---|',
  ];
  for (const rule of contract.ASSERTION_RULES) {
    // The check a rule fixes: the builder renders it from the rule alone,
    // so the facts carry the one the words name.
    const check = checkOf(rule);
    let words = `\`${samlRuleWords(rule, check)}`;
    if (rule === 'no-bearer-qualifies') {
      words += ': #1 <reason> | #2 <reason> | …[ | and N more]';
    }
    words += '`';
    if (rule === 'declined') {
      words +=
        ', followed by ` (<StatusCode>)` when the code is one of `SAML_STATUS_CODES`';
    }
    const field = contract.SAML_RULE_DIAGNOSTIC[rule];
    const diagnostic =
      field === null
        ? '—'
        : rule === 'declined'
          ? '`statusCode`, when the code is not a registered one'
          : `\`${field}\``;
    lines.push(
      `| \`${check}\` | \`${rule}\` | ${cell(words)} | ${diagnostic} |`,
    );
  }
  return lines.join('\n');
}

/**
 * A rule's check (Appendix B: fixed by the rule). auth-errors' words name
 * the rule's own check whatever the facts say, so the first check whose
 * prefix the words carry is that one — found, not copied here.
 */
function checkOf(rule) {
  for (const check of contract.ASSERTION_CHECKS) {
    const words = render('saml-assertion', { rule, check }).reason;
    if (words.startsWith(samlPrefix(check))) return check;
  }
  throw new Error(`saml: no check renders ${rule}`);
}

/** The eleven bearer candidate reasons, in the order a candidate is tested. */
function samlCandidatesTable() {
  const lines = [
    '| # | `reason` | Words |',
    '|---|---|---|',
  ];
  const lead = `${samlPrefix('bearerConfirmation')}no bearer confirmation qualifies: #1 `;
  contract.BEARER_CANDIDATE_REASONS.forEach((reason, index) => {
    const candidate =
      reason === 'several-confirmation-data' ? { reason, count: 2 } : { reason };
    const words = render('saml-assertion', {
      rule: 'no-bearer-qualifies',
      check: 'bearerConfirmation',
      candidates: [candidate],
    }).reason;
    if (!words.startsWith(lead)) {
      throw new Error(`saml-candidates: unexpected words for ${reason}`);
    }
    const said = words.slice(lead.length).replace(' 2 ', ' <n> ');
    lines.push(`| ${index + 1} | \`${reason}\` | ${cell(`\`${said}\``)} |`);
  });
  return lines.join('\n');
}

/**
 * "Configuration errors" (spec Appendix A.5, K6): each case, where it is
 * thrown and the fields it names. A case whose words list its fields is
 * rendered with one field and shown with `<fields>` in its place.
 */
function configurationTable() {
  const lines = [
    '| Thrown | `case` | `fields` | Reason | Hint |',
    '|---|---|---|---|---|',
  ];
  const rows = {
    'required-fields-missing': [
      'a required field or collaborator is missing (`ClientCredentialsProvider`, `AuthorizationCodeProvider`, the UAA authorization URL, a SAML provider without `assertionValidator`)',
      null,
    ],
    'client-secret-beside-client-authentication': [
      'a token provider constructed with both',
      ['clientSecret'],
    ],
    'saml-acs-required-with-authorization-url': [
      'a SAML provider constructed with `authorizationUrl` and no `acsUrl`',
      ['acsUrl'],
    ],
    'saml-idp-initiated-with-request-id': [
      'a SAML provider constructed with `idpInitiated` and `authnRequestId` (`fields`: both), or a login that minted or declared a request ID (`fields`: `idpInitiated`)',
      ['idpInitiated', 'authnRequestId'],
    ],
    'saml-shipped-validator-without-issuer': [
      'a SAML provider constructed with a shipped validator and no `idpEntityId`',
      ['idpEntityId'],
    ],
    'saml-token-endpoint-missing': [
      'the SAML bearer exchange without `tokenUrl` or `uaaUrl`',
      ['tokenUrl', 'uaaUrl'],
    ],
    'saml-idp-initiated-without-authorization-url': [
      'a strategy asks for the URL of an `idpInitiated` login without `authorizationUrl`',
      ['idpInitiated', 'authorizationUrl'],
    ],
    'saml-acs-mismatch': [
      'the strategy listens, or listened, elsewhere than `acsUrl`; the two addresses are `diagnostics.configuredUri` / `strategyUri`',
      ['acsUrl'],
    ],
    'saml-in-response-to-undeclared': [
      'a SAML login with no request ID minted, declared or declared absent',
      ['authnRequestId', 'idpInitiated'],
    ],
    'client-id-required-with-client-authentication': [
      'a SAML exchange or refresh with a `clientAuthentication` and no `clientId`',
      ['clientId'],
    ],
    'redirect-mismatch': [
      "a pre-built `authorizationUrl` whose `redirect_uri` the strategy did not use; the two addresses are `diagnostics.configuredUri` / `strategyUri`",
      ['authorizationUrl'],
    ],
    'oidc-discovery-needs-issuer': [
      'an OIDC endpoint to discover and no `issuerUrl`',
      ['issuerUrl'],
    ],
    'oidc-endpoint-missing': [
      'an OIDC endpoint neither configured nor discovered (`authorizationEndpoint`, `tokenEndpoint` or `deviceAuthorizationEndpoint`)',
      null,
    ],
    'certificate-pem-and-pfx': [
      '`FileCertificateMaterialLoader`: PEM and PFX paths both given',
      ['certPath', 'certPfxPath'],
    ],
    'certificate-files-missing': [
      '`FileCertificateMaterialLoader`: neither a PFX nor a whole PEM pair',
      ['certPfxPath', 'certPath', 'certKeyPath'],
    ],
    'basic-encoding-missing': [
      "`clientSecretBasic` without `encoding: 'raw' | 'form'` (`allowed: 'basic-encoding'`)",
      ['encoding'],
    ],
    'snc-partner-name-missing': [
      '`SncLogonProvider` without `partnerName`',
      ['partnerName'],
    ],
    'snc-qop-invalid': [
      "`SncLogonProvider` with another `qop` (`allowed: 'snc-qop'`)",
      ['qop'],
    ],
    'unsupported-sso-flow': [
      '`SsoProviderFactory.create` with no provider for the protocol and flow',
      [],
    ],
    'validator-clock-skew-invalid': [
      'a shipped validator with a `clockSkewMs` that is not a non-negative integer',
      ['clockSkewMs'],
    ],
    'validator-no-certificates': [
      'a shipped validator with no `idpCertificates`',
      ['idpCertificates'],
    ],
    'idp-certificate-invalid': [
      'a shipped validator with a certificate that is neither PEM nor base64 DER, or no certificate',
      ['idpCertificates'],
    ],
    'static-code-without-payload': [
      '`staticCodeStrategy` without a payload',
      ['payload'],
    ],
    'callback-port-invalid': [
      'a callback server port that is not an integer in 0..65535',
      ['port'],
    ],
  };
  for (const [kase, [when, fields]] of each(
    contract.CONFIG_CASES,
    rows,
    'configuration',
  )) {
    const words =
      fields === null
        ? render('configuration', { case: kase, fields: ['clientId'] })
        : render('configuration', { case: kase, fields });
    const reason =
      fields === null
        ? words.reason.replace('clientId', '`<fields>`')
        : words.reason;
    const named =
      fields === null
        ? '`<fields>`'
        : fields.length === 0
          ? '—'
          : fields.map((field) => `\`${field}\``).join(', ');
    lines.push(
      `| ${cell(when)} | \`${kase}\` | ${named} | ${cell(reason)} | ${cell(words.hint ?? '')} |`,
    );
  }
  return lines.join('\n');
}

export const TABLES = {
  rejected: rejectedTable,
  refusals: refusalsTable,
  configuration: configurationTable,
  saml: samlTable,
  'saml-candidates': samlCandidatesTable,
};

/** The README with every generated region replaced. */
export function generate(readme) {
  let out = readme;
  for (const [name, build] of Object.entries(TABLES)) {
    const open = `<!-- generated:refusal-table ${name} -->`;
    const close = `<!-- /generated:refusal-table ${name} -->`;
    const start = out.indexOf(open);
    const end = out.indexOf(close);
    if (start < 0 || end < start) {
      throw new Error(`README.md: no region for the ${name} table`);
    }
    out = `${out.slice(0, start + open.length)}\n${build()}\n${out.slice(end)}`;
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const readme = readFileSync(README, 'utf8');
  const generated = generate(readme);
  if (process.argv.includes('--check')) {
    if (generated !== readme) {
      console.error(
        'README.md refusal tables differ from the generated ones: run `npm run docs:tables`',
      );
      process.exit(1);
    }
  } else if (generated !== readme) {
    writeFileSync(README, generated);
  }
}
