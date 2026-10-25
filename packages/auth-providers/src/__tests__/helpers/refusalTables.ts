/**
 * The README's refusal tables: every word comes from auth-errors' `render`,
 * every row set from the allowlists of interfaces-auth as auth-errors sees
 * it (`contract`) — nothing here copies a sentence. A table that meets a
 * value it has no row text for throws (`rowsFor`), so a new problem or
 * verdict cannot be left out silently.
 *
 * Each table lives between `<!-- generated:refusal-table NAME -->` and
 * `<!-- /generated:refusal-table NAME -->`. The rows are rendered here; the
 * prose around them is written by hand. The "When", "The rejection" and
 * "Thrown" cells are this repository's own words, kept here.
 */
import { count, httpStatus } from '@mcp-abap-adt/auth-errors';
import {
  contract,
  type GeneratedRegion,
  markdownCell,
  render,
  rowsFor,
} from '@mcp-abap-adt/auth-errors/tables';

type Words = ReturnType<typeof render>;

/**
 * `render` over facts whose shape depends on a value known only at run
 * time — a verdict's own facts, a rule's own check, a case's own fields.
 * The words are `render`'s; only the compile-time correlation is given up.
 */
const renderFacts = render as (kind: string, facts: object) => Words;

/** A branded integer the type requires, made by the main entry's maker. */
function branded<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Error(`refusal tables: ${what}`);
  return value;
}

const quoted = (text: string): string => `"${text}"`;

/** "What `rejected()` answers": the verdicts of `system-refused`. */
function rejectedTable(): string {
  const own = (
    [
      ['Basic', 'user-password'],
      ['certificate', 'client-certificate'],
      ['SAML cookies', 'saml-session'],
      ['fixed token', 'token'],
    ] as const
  )
    .map(
      ([provider, credential]) =>
        `${provider} ${quoted(render('credential-refused', { credential, at: 'request' }).reason)}`,
    )
    .join('; ');
  const status = (value: number) =>
    branded(httpStatus(value), `no HTTP status ${value}`);
  const examples: Record<string, { rejection: string; facts: object }> = {
    'not-authorized': { rejection: '`403`', facts: { status: status(403) } },
    redirected: {
      rejection: '`3xx`, e.g. `302`',
      facts: { status: status(302) },
    },
    'system-failed': {
      rejection: '`5xx`, e.g. `503`',
      facts: { status: status(503) },
    },
    'other-status': {
      rejection: 'any other status, e.g. `404`',
      facts: { status: status(404) },
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
    `| \`401\`, \`RFC_LOGON_FAILURE\` | \`credential-refused\` | their own refusal: ${markdownCell(own)} | one renewal; Ok only if the credential changed |`,
  ];
  for (const [verdict, example] of rowsFor(
    contract.SYSTEM_REFUSED_VERDICTS,
    examples,
    'rejected',
  )) {
    const logon = renderFacts('system-refused', {
      verdict,
      ...example.facts,
      at: 'logon',
    });
    const request = renderFacts('system-refused', {
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
      `| ${example.rejection} | \`system-refused\` \`${verdict}\` | ${markdownCell(words + hint)} | ${tokens} |`,
    );
  }
  return lines.join('\n');
}

/** "Refusals": client certificate, client authentication, binding, TLS. */
function refusalsTable(): string {
  const lines = ['| When | Kind | Reason | Hint |', '|---|---|---|---|'];
  const row = (when: string, kind: string, words: Words): void => {
    lines.push(
      `| ${when} | ${kind} | ${markdownCell(words.reason)} | ${markdownCell(words.hint ?? '')} |`,
    );
  };
  for (const [problem, when] of rowsFor(
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
  for (const [problem, when] of rowsFor(
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
  for (const [problem, when] of rowsFor(
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
  const unknownReason = render('unknown', {
    operation: 'token-request',
  }).reason;
  const unknownTail = ' (unknown error)';
  const lead = unknownReason.endsWith(unknownTail)
    ? unknownReason.slice(0, -unknownTail.length)
    : unknownReason;
  const groups = new Map<
    string,
    { says: string; hint: string | undefined; codes: string[] }
  >();
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
      hint === undefined
        ? { reason: `\`<operation>\` failed: ${says} (\`<code>\`)` }
        : { reason: `\`<operation>\` failed: ${says} (\`<code>\`)`, hint },
    );
  }
  return lines.join('\n');
}

/** The quoted prefix every `saml-assertion` reason starts with. */
const samlPrefix = (check: string): string =>
  `the SAML assertion was refused (${check}): `;

/**
 * A rule's words with a count of two shown as `<n>`: rendered with and
 * without the count, so only a rule whose words name it is rewritten.
 */
function samlRuleWords(rule: string, check: string): string {
  const plain = renderFacts('saml-assertion', { rule, check }).reason;
  const counted = renderFacts('saml-assertion', {
    rule,
    check,
    count: branded(count(2), 'no count 2'),
  }).reason;
  const words = counted === plain ? plain : counted.replace(' 2 ', ' <n> ');
  const prefix = samlPrefix(check);
  if (!words.startsWith(prefix)) {
    throw new Error(`saml: unexpected words for ${rule}`);
  }
  return words.slice(prefix.length);
}

/**
 * A rule's check (fixed by the rule). auth-errors' words name the rule's own
 * check whatever the facts say, so the first check whose prefix the words
 * carry is that one — found, not copied here.
 */
function checkOf(rule: string): string {
  for (const check of contract.ASSERTION_CHECKS) {
    const words = renderFacts('saml-assertion', { rule, check }).reason;
    if (words.startsWith(samlPrefix(check))) return check;
  }
  throw new Error(`saml: no check renders ${rule}`);
}

/**
 * "Refusal messages": every SAML validation rule, in the allowlist's order —
 * its check, its words after the common prefix, and the one diagnostic it
 * may carry.
 */
function samlTable(): string {
  const lines = [
    '| `check` | `rule` | Words, after `the SAML assertion was refused (<check>): ` | Diagnostic |',
    '|---|---|---|---|',
  ];
  for (const rule of contract.ASSERTION_RULES) {
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
      `| \`${check}\` | \`${rule}\` | ${markdownCell(words)} | ${diagnostic} |`,
    );
  }
  return lines.join('\n');
}

/** The eleven bearer candidate reasons, in the order a candidate is tested. */
function samlCandidatesTable(): string {
  const lines = ['| # | `reason` | Words |', '|---|---|---|'];
  const lead = `${samlPrefix('bearerConfirmation')}no bearer confirmation qualifies: #1 `;
  contract.BEARER_CANDIDATE_REASONS.forEach((reason, index) => {
    const candidate =
      reason === 'several-confirmation-data'
        ? { reason, count: branded(count(2), 'no count 2') }
        : { reason };
    const words = renderFacts('saml-assertion', {
      rule: 'no-bearer-qualifies',
      check: 'bearerConfirmation',
      candidates: [candidate],
    }).reason;
    if (!words.startsWith(lead)) {
      throw new Error(`saml-candidates: unexpected words for ${reason}`);
    }
    const said = words.slice(lead.length).replace(' 2 ', ' <n> ');
    lines.push(
      `| ${index + 1} | \`${reason}\` | ${markdownCell(`\`${said}\``)} |`,
    );
  });
  return lines.join('\n');
}

/** Where a configuration case is thrown, and the fields it names (`null`: any). */
const CONFIGURATION_ROWS: Record<
  string,
  readonly [string, readonly string[] | null]
> = {
  'required-fields-missing': [
    'a required field or collaborator is missing: every token provider (and `inBrowser`, `fromTerminal`, `toConsole`, `SsoProviderFactory.create`) without a usable `renewal`, `ClientCredentialsProvider` and `AuthorizationCodeProvider` without `uaaUrl`, `clientId`, or `clientSecret` and no `clientAuthentication`, a SAML provider without `assertionValidator`, a shipped validator without `replayStore`; an authorization strategy without a part or the redirect it needs — `manualPasteStrategy`, `manualSamlResponseStrategy` and `externalCodeStrategy` without `redirectUri`, a redirect protocol over a transport that advertises none (`redirectUri`), `composeAuthorization` without `presentation`, `transport`, `protocol` or `endpoint`, `openInBrowser` without `browser` (`presentation`), `consumerPresentation` without `show`, `consumerAnswer` without `receive`, `consumerHandoff` without `provide`; also an `SncLogonProvider` `myName` that is not a string (a known wording limit)',
    null,
  ],
  'invalid-value': [
    "a configured value that cannot be used: an `authorizationUrl` that does not parse (`AuthorizationCodeProvider` at construction and at login); a `persistence` that is not an object with a callable `report` (every token provider); `refreshStatePersistence` with `onWriteFailure` missing or not `'continue'` / `'fail'`, or a `write` that is not a function (each named); a part of an authorization strategy that cannot be used: an `endpoint` that URL parsing would change or that is `/` or `/submit` (`endpoint`), a `redirectUri` that is not an absolute `http(s)` URL (`redirectUri`), a `browser` without an `open` function — a browser name included (`presentation`), a part without its methods (`presentation`, `transport`, `protocol`), a `remoteHint` that is not a function (`transport`), a `read` that is not a function (`read`), an `onFailure` that is not a function (`show`), a terminal with a protocol that has no paste words (`protocol`); an authorization URL a protocol cannot read a `state` from — none, empty or repeated (`authorizationUrl`)",
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
    'a pre-built `authorizationUrl` whose `redirect_uri` the strategy did not use; the two addresses are `diagnostics.configuredUri` / `strategyUri`',
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
    "a listener `port` (or a callback strategy's) that is not an integer in 0..65535, at construction and again when it opens",
    ['port'],
  ],
};

/**
 * "Configuration errors": each case, where it is thrown and the fields it
 * names. A case whose words list its fields is rendered with one field and
 * shown with `<fields>` in its place.
 */
function configurationTable(): string {
  const lines = [
    '| Thrown | `case` | `fields` | Reason | Hint |',
    '|---|---|---|---|---|',
  ];
  for (const [kase, [when, fields]] of rowsFor(
    contract.CONFIG_CASES,
    CONFIGURATION_ROWS,
    'configuration',
  )) {
    const words =
      fields === null
        ? renderFacts('configuration', { case: kase, fields: ['clientId'] })
        : renderFacts('configuration', { case: kase, fields });
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
      `| ${markdownCell(when)} | \`${kase}\` | ${named} | ${markdownCell(reason)} | ${markdownCell(words.hint ?? '')} |`,
    );
  }
  return lines.join('\n');
}

const TABLES: readonly (readonly [string, () => string])[] = [
  ['rejected', rejectedTable],
  ['refusals', refusalsTable],
  ['saml', samlTable],
  ['saml-candidates', samlCandidatesTable],
  ['configuration', configurationTable],
];

/** The README's five refusal tables, each as its generated region. */
export function refusalTableRegions(): GeneratedRegion[] {
  return TABLES.map(([name, build]) => ({
    open: `<!-- generated:refusal-table ${name} -->`,
    close: `<!-- /generated:refusal-table ${name} -->`,
    body: build(),
  }));
}
