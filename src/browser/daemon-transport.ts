import {
  CHALLENGE_HEADER, PROOF_HEADER, authorizationHeader, daemonTokenPath, newNonce, readDaemonTokenOrNull, signParts, verifyResponseProof,
} from '../daemon-auth.js';
import { BrowserConnectError } from '../errors.js';
import { DAEMON_HOST, DEFAULT_DAEMON_PORT, isIgnorableDaemonPortEnv, unsupportedDaemonPortEnvMessage } from '../constants.js';

const DAEMON_PORT = DEFAULT_DAEMON_PORT;
const DAEMON_URL = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
const OPENCLI_HEADERS = { 'X-OpenCLI': '1' };

class UnsupportedDaemonPortEnvError extends Error {
  constructor(value: string) {
    super(unsupportedDaemonPortEnvMessage(value));
    this.name = 'UnsupportedDaemonPortEnvError';
  }
}

/** OPENCLI_DAEMON_MANAGED=1: an external manager owns the daemon's lifetime. */
export function isDaemonManaged(): boolean {
  return process.env.OPENCLI_DAEMON_MANAGED === '1';
}

/**
 * Whatever answered on the daemon port could not prove it holds the token.
 * Nothing from that response (status, pid, version) may be used, and the CLI
 * must neither spawn a replacement nor send it a shutdown.
 */
export class UnauthenticatedDaemonError extends BrowserConnectError {
  constructor(reason: 'no-token' | 'bad-proof') {
    super(
      reason === 'no-token'
        ? `Something is listening on port ${DEFAULT_DAEMON_PORT}, but the daemon token at ${daemonTokenPath()} cannot be read`
        : `An unauthenticated program is listening on port ${DEFAULT_DAEMON_PORT}: its response did not carry a valid opencli daemon proof`,
      reason === 'no-token'
        ? 'Make sure the token file exists, is owned by you with mode 600, and OPENCLI_DAEMON_TOKEN_FILE matches the daemon.'
        : `Its reply was ignored. Either another program (possibly another user's) holds port ${DEFAULT_DAEMON_PORT}, ` +
          'or the running daemon uses a different token file. Identify it (e.g. lsof -nP -iTCP:' + DEFAULT_DAEMON_PORT +
          ' -sTCP:LISTEN), stop it yourself, and retry.',
      'daemon-unauthenticated',
    );
    this.name = 'UnauthenticatedDaemonError';
  }
}

function assertSupportedDaemonPortEnv(): void {
  const value = process.env.OPENCLI_DAEMON_PORT;
  if (!isIgnorableDaemonPortEnv(value)) throw new UnsupportedDaemonPortEnvError(value!);
}

export interface DaemonStatus {
  ok: boolean;
  pid: number;
  uptime: number;
  daemonVersion?: string;
  extensionConnected: boolean;
  extensionVersion?: string;
  extensionCompatRange?: string;
  contextId?: string;
  profileRequired?: boolean;
  profileDisconnected?: boolean;
  profiles?: BrowserProfileStatus[];
  pending: number;
  commandResultUnknown?: number;
  memoryMB: number;
  port: number;
}

export interface BrowserProfileStatus {
  contextId: string;
  extensionConnected: boolean;
  extensionVersion?: string;
  extensionCompatRange?: string;
  pending: number;
  lastSeenAt?: number;
}

export type DaemonHealth =
  | { state: 'stopped'; status: null }
  | { state: 'no-extension'; status: DaemonStatus }
  | { state: 'profile-required'; status: DaemonStatus }
  | { state: 'profile-disconnected'; status: DaemonStatus }
  | { state: 'ready'; status: DaemonStatus };

/**
 * HMAC signature over method, the exact path+query fetch will send, and the
 * body hash; the token itself never leaves this process. Re-read per request:
 * the daemon may create the token file after the CLI started.
 */
function authHeader(token: string | null, method: string, url: URL, body: RequestInit['body']): Record<string, string> {
  if (!token) return {};
  if (body != null && typeof body !== 'string' && !(body instanceof Uint8Array)) {
    throw new TypeError('requestDaemon only supports string or Uint8Array bodies');
  }
  return { Authorization: authorizationHeader(signParts(token, method, url.pathname + url.search, body ?? undefined)) };
}

/**
 * Signed request + authenticated response. The returned Response is rebuilt
 * from bytes whose X-OpenCLI-Proof was verified; an unverifiable reply throws
 * UnauthenticatedDaemonError and is never surfaced.
 */
export async function requestDaemon(pathname: string, init?: RequestInit & { timeout?: number }): Promise<Response> {
  assertSupportedDaemonPortEnv();
  const { timeout = 2000, headers, ...rest } = init ?? {};
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const url = new URL(`${DAEMON_URL}${pathname}`);
    const token = readDaemonTokenOrNull();
    const challenge = newNonce();
    const res = await fetch(url.href, {
      ...rest,
      headers: {
        ...OPENCLI_HEADERS,
        ...authHeader(token, rest.method ?? 'GET', url, rest.body),
        ...headers,
        [CHALLENGE_HEADER]: challenge,
      },
      signal: controller.signal,
    });
    const body = new Uint8Array(await res.arrayBuffer());
    if (!token) throw new UnauthenticatedDaemonError('no-token');
    if (!verifyResponseProof(token, challenge, res.status, body, res.headers.get(PROOF_HEADER))) {
      throw new UnauthenticatedDaemonError('bad-proof');
    }
    return new Response(body.length ? body : null, { status: res.status, headers: res.headers });
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchDaemonStatus(opts?: { timeout?: number; contextId?: string; preferredContextId?: string }): Promise<DaemonStatus | null> {
  try {
    const query = new URLSearchParams({
      ...(opts?.contextId ? { contextId: opts.contextId } : {}),
      ...(opts?.preferredContextId ? { preferredContextId: opts.preferredContextId } : {}),
    }).toString();
    const res = await requestDaemon(`/status${query ? `?${query}` : ''}`, { timeout: opts?.timeout ?? 2000 });
    // A running daemon that rejects us is not "stopped" — spawning another
    // would only hit EADDRINUSE. Say why instead.
    if (res.status === 401) {
      throw new BrowserConnectError(
        'opencli daemon rejected the request signature (Unauthorized)',
        `The daemon proved it holds the token at ${daemonTokenPath()} but rejected this request ` +
        '(system clock off by more than 30s, or a replayed nonce). Check the clock and retry.',
        'daemon-unauthenticated',
      );
    }
    if (!res.ok) return null;
    return await res.json() as DaemonStatus;
  } catch (err) {
    if (err instanceof UnsupportedDaemonPortEnvError || err instanceof BrowserConnectError) throw err;
    return null;
  }
}

export async function getDaemonHealth(opts?: { timeout?: number; contextId?: string; preferredContextId?: string }): Promise<DaemonHealth> {
  const status = await fetchDaemonStatus(opts);
  if (!status) return { state: 'stopped', status: null };
  if (status.profileRequired) return { state: 'profile-required', status };
  if (status.profileDisconnected) return { state: 'profile-disconnected', status };
  if (!status.extensionConnected) return { state: 'no-extension', status };
  return { state: 'ready', status };
}

export async function requestDaemonShutdown(opts?: { timeout?: number }): Promise<boolean> {
  if (isDaemonManaged()) {
    throw new BrowserConnectError(
      'Refusing to stop the daemon: OPENCLI_DAEMON_MANAGED=1',
      'The daemon is managed externally; stop it with your service manager.',
      'daemon-not-running',
    );
  }
  try {
    const res = await requestDaemon('/shutdown', { method: 'POST', timeout: opts?.timeout ?? 5000 });
    return res.ok;
  } catch (err) {
    if (err instanceof UnsupportedDaemonPortEnvError || err instanceof BrowserConnectError) throw err;
    return false;
  }
}
