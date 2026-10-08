/**
 * The one HTTP listener behind `loopback6`, `loopback4` and `loopback`
 * (spec §6d.2, §6d.3): payload-agnostic, parameterised by where it binds
 * and what it advertises. Not exported from the package.
 *
 * One owner, one release point. The sockets belong to one `open`: released
 * on the first terminal outcome — `use` returning or throwing, an `end`
 * verdict, the signal — and `open` settles only once every listening socket
 * is closed, so a settled `open` means the port is free. No timer of the
 * package's choosing bounds it (spec §6a).
 *
 * Per request, in this order: the `Host` check (a loopback authority with
 * the bound port, from a loopback peer); literal dispatch of the pathname
 * to `endpoint`, `/` or `/submit` — read with `URL`, compared as strings;
 * the gate (closed until armed); the form token on `/submit`; only then the
 * protocol's judge, which alone decides what an answer is. Nothing of an
 * answer is logged: a refusal's line names its reason and the count.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  ANSWER_REFUSALS,
  type AnswerJudge,
  type AnswerRefusal,
  type AnswerTransportOptions,
  type AuthorizationAnswer,
  type IAnswerChannel,
  type IArmedChannel,
  type PasteWords,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { promptableUrl } from '../../auth/announce';
import { ownOptions } from '../../auth/configuration';
import {
  abortedLogin,
  failedLogin,
  loginFailure,
  portInUse,
} from '../../auth/interactiveLogin';
import { readSafely } from '../../auth/knownCodes';
import { logQuietly } from '../../auth/tokenRequest';
import { ANSWER_WORDS } from '../answerWords';
import { oneValue } from '../protocol/readPaste';
import { mintSecret, sameSecret } from '../secrets';
import { answersLoopback } from './authority';
import {
  addressInUse,
  bindFailure,
  unavailableAddress,
  validatePort,
} from './binding';
import { afterFlush, trackConnections } from './connections';
import { checkedEndpoint, PASTE_PAGE, PASTE_SUBMIT } from './endpoint';
import { endFailure } from './endVerdict';
import { CALLBACK_CSP, errorHtml, pastePageHtml, successHtml } from './pages';

/** One address a listener binds. */
export interface ListenerBind {
  readonly address: string;
  /** Skipped when the machine does not have the address (C3). */
  readonly ifAvailable: boolean;
}

/** Where a listener binds and what it advertises. */
export interface ListenerPlan {
  /** `0` binds an ephemeral port. */
  readonly port: number;
  /** In order: the first takes `port`, every later one the port it got. */
  readonly binds: readonly [ListenerBind, ...ListenerBind[]];
  /** The host of the origin it advertises: an address it binds, or `localhost`. */
  readonly advertises: string;
  /** The address an SSH tunnel to this machine forwards to. */
  readonly tunnelsTo: string;
}

/** The urlencoded body of a POST: as the SAML route had it, 5 MB. */
const FORM_LIMIT = 5 * 1024 * 1024;

const REFUSALS: ReadonlySet<string> = new Set(ANSWER_REFUSALS);

/** K8: the open ended before an answer was accepted. */
const callbackClosed = () => loginFailure({ outcome: 'callback-closed' });

/** The options a listener reads, once, as own data. */
interface ListenerOptions {
  readonly signal: AbortSignal | undefined;
  readonly logger: ILogger | undefined;
  readonly paste: PasteWords | undefined;
  readonly methods: ReadonlySet<'GET' | 'POST'>;
  readonly endpoint: string;
}

/** Paste words as own data strings, else none. */
function pasteWordsOf(value: unknown): PasteWords | undefined {
  const own = ownOptions<Partial<PasteWords>>(value);
  return typeof own.prompt === 'string' && typeof own.instructions === 'string'
    ? Object.freeze({ prompt: own.prompt, instructions: own.instructions })
    : undefined;
}

/** The methods a redirect arrives with: `GET` / `POST` only. */
function methodsOf(value: unknown): ReadonlySet<'GET' | 'POST'> {
  const methods = new Set<'GET' | 'POST'>();
  if (!Array.isArray(value)) return methods;
  try {
    for (const method of value as unknown[]) {
      if (method === 'GET' || method === 'POST') methods.add(method);
    }
  } catch {
    // An unreadable list: no method.
  }
  return methods;
}

function readOptions(options: AnswerTransportOptions): ListenerOptions {
  const own =
    ownOptions<Partial<Record<keyof AnswerTransportOptions, unknown>>>(options);
  const { signal, logger } = own;
  return {
    endpoint: checkedEndpoint(own.endpoint),
    signal: signal instanceof AbortSignal ? signal : undefined,
    logger:
      logger !== null && typeof logger === 'object'
        ? (logger as ILogger)
        : undefined,
    paste: own.paste === undefined ? undefined : pasteWordsOf(own.paste),
    methods: methodsOf(own.callbackMethods),
  };
}

/** The request target's path and query: origin-form only. */
function targetOf(
  url: string | undefined,
): { readonly pathname: string; readonly query: URLSearchParams } | undefined {
  if (url === undefined || !url.startsWith('/')) return undefined;
  // The raw target up to the first `?`, as a string: no dot segment
  // resolved, nothing decoded, so only the exact advertised path matches.
  // The query alone is read with `URLSearchParams`.
  const mark = url.indexOf('?');
  return mark < 0
    ? { pathname: url, query: new URLSearchParams() }
    : {
        pathname: url.slice(0, mark),
        query: new URLSearchParams(url.slice(mark + 1)),
      };
}

type Route = 'redirect-get' | 'redirect-post' | 'page' | 'submit';

/**
 * Literal dispatch: the pathname compared as a string to the three paths,
 * exactly — no pattern, no case folding, no trailing-slash equivalence.
 */
function routeOf(
  pathname: string,
  method: string | undefined,
  options: ListenerOptions,
): Route | undefined {
  if (pathname === options.endpoint) {
    if (method === 'GET' && options.methods.has('GET')) return 'redirect-get';
    if (method === 'POST' && options.methods.has('POST')) {
      return 'redirect-post';
    }
    return undefined;
  }
  if (options.paste === undefined) return undefined;
  if (pathname === PASTE_PAGE && method === 'GET') return 'page';
  if (pathname === PASTE_SUBMIT && method === 'POST') return 'submit';
  return undefined;
}

/** Whether a request's body is urlencoded (its media type, any parameters). */
function urlencoded(req: http.IncomingMessage): boolean {
  const type = req.headers['content-type'];
  if (typeof type !== 'string') return false;
  const semicolon = type.indexOf(';');
  const media = (semicolon < 0 ? type : type.slice(0, semicolon))
    .trim()
    .toLowerCase();
  return media === 'application/x-www-form-urlencoded';
}

/**
 * The urlencoded body of a POST, read to its end: `too-large` past 5 MB
 * (the rest read and dropped), empty parameters for any other type. A
 * request that never finishes never settles: the release destroys it.
 */
function readForm(
  req: http.IncomingMessage,
): Promise<URLSearchParams | 'too-large'> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size <= FORM_LIMIT) chunks.push(chunk);
    });
    req.on('end', () => {
      if (size > FORM_LIMIT) {
        resolve('too-large');
        return;
      }
      resolve(
        urlencoded(req)
          ? new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
          : new URLSearchParams(),
      );
    });
    req.on('error', () => undefined);
  });
}

/** Plain text, said to be plain text, in UTF-8: never rendered as markup. */
function sendText(res: http.ServerResponse, status: number, text: string) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end(text);
}

/** An HTML page, said to be one, in UTF-8. */
function sendHtml(res: http.ServerResponse, status: number, html: string) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(html);
}

/** What the listener reads of a verdict; anything else is no verdict. */
type ReadVerdict =
  | { readonly verdict: 'accept' }
  | { readonly verdict: 'refuse'; readonly reason: AnswerRefusal }
  | {
      readonly verdict: 'end';
      readonly error: unknown;
      readonly shown: string | undefined;
    };

/** The judge's answer, each field read safely; `undefined` for a throw. */
function judged(
  judge: AnswerJudge<unknown>,
  answer: AuthorizationAnswer,
): ReadVerdict | undefined {
  let raw: unknown;
  try {
    raw = judge(answer);
  } catch {
    return undefined;
  }
  const verdict = readSafely(raw, 'verdict');
  if (verdict === 'accept') return { verdict };
  if (verdict === 'refuse') {
    const reason = readSafely(raw, 'reason');
    return typeof reason === 'string' && REFUSALS.has(reason)
      ? { verdict, reason: reason as AnswerRefusal }
      : undefined;
  }
  if (verdict === 'end') {
    const shown = readSafely(raw, 'shown');
    return {
      verdict,
      error: readSafely(raw, 'error'),
      shown: typeof shown === 'string' ? shown : undefined,
    };
  }
  return undefined;
}

/** This attempt's judge and, with paste words, its form token. */
interface Armed {
  readonly judge: AnswerJudge<unknown>;
  readonly formToken: string | undefined;
}

/**
 * Opens a listener per `plan`, runs `use` with its channel, releases.
 * Settles on the first terminal outcome, and only once released.
 */
export async function openHttpListener<TReturn>(
  plan: ListenerPlan,
  options: AnswerTransportOptions,
  use: (channel: IAnswerChannel) => Promise<TReturn>,
): Promise<TReturn> {
  validatePort(plan.port);
  const routing = readOptions(options);
  const { signal, logger, paste, endpoint } = routing;
  if (signal?.aborted) throw abortedLogin('browser');

  /** The port the OS gave the first bind; `0` until then. */
  let boundPort = 0;
  let armed: Armed | undefined;
  let ignored = 0;

  const connections = trackConnections('destroy');

  let answerSettled = false;
  let resolveAnswer!: () => void;
  let rejectAnswer!: (error: Error) => void;
  const answerPromise = new Promise<void>((resolve, reject) => {
    resolveAnswer = resolve;
    rejectAnswer = reject;
  });
  // Marked handled at creation: `use` may never ask for it.
  void answerPromise.catch(() => undefined);
  const settleAnswer = (outcome: { error: Error } | undefined): void => {
    if (answerSettled) return;
    answerSettled = true;
    if (outcome === undefined) resolveAnswer();
    else rejectAnswer(outcome.error);
  };

  let scopeSettled = false;
  let resolveScope!: (value: TReturn) => void;
  let rejectScope!: (error: unknown) => void;
  const scopePromise = new Promise<TReturn>((resolve, reject) => {
    resolveScope = resolve;
    rejectScope = reject;
  });

  /**
   * Settles once every bind begun has finished: a listen still resolving
   * when the scope ends completes afterwards and is closed then.
   */
  let binding: Promise<void> = Promise.resolve();

  /** The one place an open ends. Everything after the first call is a no-op. */
  const endScope = (outcome: { value: TReturn } | { error: unknown }): void => {
    if (scopeSettled) return;
    scopeSettled = true;
    signal?.removeEventListener('abort', onAbort);
    settleAnswer({ error: callbackClosed() });
    connections.release();
    void binding.then(() => {
      // Release first, then settle: a settled open means the port is free.
      connections.release();
      if ('value' in outcome) resolveScope(outcome.value);
      else rejectScope(outcome.error);
    });
  };

  function onAbort(): void {
    endScope({ error: abortedLogin('browser', ignored) });
  }

  /** Counted, logged with its reason only, ignored: the login waits. */
  const refused = (reason: AnswerRefusal): void => {
    ignored += 1;
    logQuietly(() =>
      logger?.warn('[listener] refused an answer', { reason, ignored }),
    );
  };

  const refuseInText = (res: http.ServerResponse, reason: AnswerRefusal) => {
    sendText(res, 400, ANSWER_WORDS[reason]);
    refused(reason);
  };

  /** The judge's verdict on one answer, answered per §6d.3.2. */
  const answerWith = (
    res: http.ServerResponse,
    current: Armed,
    answer: AuthorizationAnswer,
  ): void => {
    const verdict = judged(current.judge, answer);
    if (verdict === undefined) {
      // A judge that throws or answers no verdict: a fixed page, nothing of
      // it anywhere; the login fails.
      sendHtml(res, 500, errorHtml('The callback could not be handled.'));
      const error = failedLogin(undefined);
      afterFlush(res, () => {
        settleAnswer({ error });
        endScope({ error });
      });
      return;
    }
    if (verdict.verdict === 'accept') {
      sendHtml(res, 200, successHtml);
      afterFlush(res, () => settleAnswer(undefined));
      return;
    }
    if (verdict.verdict === 'end') {
      // `shown` reaches the escaped page only.
      sendHtml(res, 400, errorHtml(verdict.shown ?? 'The login was refused.'));
      const error = endFailure(verdict.error);
      afterFlush(res, () => {
        settleAnswer({ error });
        endScope({ error });
      });
      return;
    }
    if (answer.via === 'form' && current.formToken !== undefined && paste) {
      sendHtml(
        res,
        400,
        pastePageHtml(current.formToken, paste, ANSWER_WORDS[verdict.reason]),
      );
      refused(verdict.reason);
      return;
    }
    refuseInText(res, verdict.reason);
  };

  const serve = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', CALLBACK_CSP);
    // One answer per connection: nothing pipelined is queued behind it.
    res.setHeader('Connection', 'close');
    // Before any route, page or token: a name this listener does not
    // answer for (DNS rebinding), or a peer off this machine.
    if (
      !answersLoopback(req.headers.host, req.socket.remoteAddress, boundPort)
    ) {
      refuseInText(res, 'host');
      return;
    }
    const target = targetOf(req.url);
    const route =
      target === undefined
        ? undefined
        : routeOf(target.pathname, req.method, routing);
    if (target === undefined || route === undefined) {
      sendText(res, 404, 'Not found');
      return;
    }
    // Closed until armed: no answer is judged, no form (no token) served.
    const current = armed;
    if (current === undefined) {
      refuseInText(res, 'not-armed');
      return;
    }
    switch (route) {
      case 'redirect-get':
        answerWith(res, current, {
          via: 'redirect',
          method: 'GET',
          params: target.query,
        });
        return;
      case 'redirect-post': {
        const form = await readForm(req);
        if (form === 'too-large') {
          sendText(res, 413, 'Error: the request is too large.');
          return;
        }
        answerWith(res, current, {
          via: 'redirect',
          method: 'POST',
          params: form,
        });
        return;
      }
      case 'page':
        if (current.formToken === undefined || paste === undefined) {
          sendText(res, 404, 'Not found');
          return;
        }
        sendHtml(res, 200, pastePageHtml(current.formToken, paste));
        return;
      case 'submit': {
        const form = await readForm(req);
        if (form === 'too-large') {
          sendText(res, 413, 'Error: the request is too large.');
          return;
        }
        // The channel's evidence first: submitted through the page this
        // listener served (one token, constant time).
        if (
          current.formToken === undefined ||
          !sameSecret(current.formToken, oneValue(form, 'form_token'))
        ) {
          refuseInText(res, 'form-token');
          return;
        }
        answerWith(res, current, {
          via: 'form',
          text: oneValue(form, 'input') ?? '',
        });
        return;
      }
    }
  };

  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    serve(req, res).catch(() => {
      // Never Express's default handler, never the thrown text.
      if (res.headersSent) res.end();
      else sendHtml(res, 500, errorHtml('The callback could not be handled.'));
    });
  };

  /** Listens on one address; settles once bound or refused. */
  const listenOn = (address: string, onPort: number): Promise<number> =>
    new Promise<number>((resolve, reject) => {
      const server = http.createServer(handler);
      connections.watch(server);
      const refusedBind = (error: Error) => reject(error);
      server.once('error', refusedBind);
      server.listen({ port: onPort, host: address }, () => {
        server.removeListener('error', refusedBind);
        // A listener's later failure ends the open in fixed words.
        server.on('error', (error: Error) => {
          endScope({ error: failedLogin(error) });
        });
        resolve((server.address() as AddressInfo).port);
      });
    });

  signal?.addEventListener('abort', onAbort, { once: true });

  const bindAll = async (): Promise<number> => {
    const [first, ...more] = plan.binds;
    boundPort = await listenOn(first.address, plan.port);
    for (const bind of more) {
      if (scopeSettled) break;
      try {
        await listenOn(bind.address, boundPort);
      } catch (error) {
        if (bind.ifAvailable && unavailableAddress(error)) continue;
        // Taken on the second family — an ephemeral port as much as a
        // fixed one: the advertised name resolves there too, so staying on
        // the first alone would hand its holder the answer (spec §6a1).
        if (addressInUse(error)) throw portInUse(boundPort);
        throw error;
      }
    }
    return boundPort;
  };

  const bindingPort = bindAll();
  binding = bindingPort.then(
    () => undefined,
    () => undefined,
  );

  bindingPort.then(
    (port) => {
      // Aborted while binding: `endScope` closes what was bound.
      if (scopeSettled) return;
      const origin = `http://${plan.advertises}:${port}`;
      const redirectUri = `${origin}${endpoint}`;
      const shownPage = promptableUrl(`${origin}${PASTE_PAGE}`);
      const channel: IAnswerChannel = Object.freeze({
        redirectUri,
        waitingOn: redirectUri,
        routeHint:
          paste === undefined
            ? undefined
            : 'If your browser is on another machine, open an SSH tunnel to ' +
              `this one (ssh -L ${port}:${plan.tunnelsTo}:${port} <this machine>), ` +
              `then paste the answer at ${shownPage ?? 'the callback port on localhost'}`,
        arm(judge: AnswerJudge<unknown>): IArmedChannel {
          if (typeof judge !== 'function' || armed !== undefined) {
            throw loginFailure({ outcome: 'failed' });
          }
          // A new form token per attempt, minted only when the page exists.
          armed = {
            judge,
            formToken: paste === undefined ? undefined : mintSecret(),
          };
          return Object.freeze({ answer: () => answerPromise });
        },
      });
      new Promise<TReturn>((resolve) => resolve(use(channel))).then(
        (value) => endScope({ value }),
        (error: unknown) => endScope({ error }),
      );
    },
    (error: unknown) => {
      endScope({ error: bindFailure(error, plan.port) });
    },
  );

  return await scopePromise;
}
