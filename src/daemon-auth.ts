/**
 * Shared-secret authentication between the CLI, the daemon and the Browser
 * Bridge extension.
 *
 * The token lives in a 0600 file (default ~/.opencli/daemon-token, override
 * with OPENCLI_DAEMON_TOKEN_FILE). The daemon creates it on first start; the
 * CLI only reads it. The token itself is never sent over the wire (requests
 * are HMAC-signed, see below) and never appears in logs or error messages.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { IncomingMessage } from 'node:http';

const TOKEN_RE = /^[A-Za-z0-9_-]{32,}$/;
const POSIX = process.platform !== 'win32';

export class DaemonTokenError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message);
    this.name = 'DaemonTokenError';
  }
}

export function daemonTokenPath(): string {
  return process.env.OPENCLI_DAEMON_TOKEN_FILE || path.join(os.homedir(), '.opencli', 'daemon-token');
}

/** Read and validate the token file. Throws DaemonTokenError (never includes the token). */
export function readDaemonToken(file: string = daemonTokenPath()): string {
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new DaemonTokenError(`Daemon token file ${file} cannot be read (${code ?? 'error'})`, code);
  }
  if (lst.isSymbolicLink()) throw new DaemonTokenError(`Daemon token file ${file} is a symbolic link; refusing to use it`);
  if (!lst.isFile()) throw new DaemonTokenError(`Daemon token file ${file} is not a regular file`);

  // O_NOFOLLOW + fstat closes the swap-after-lstat race on POSIX.
  let fd: number;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new DaemonTokenError(`Daemon token file ${file} cannot be opened (${code ?? 'error'})`, code);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new DaemonTokenError(`Daemon token file ${file} is not a regular file`);
    if (POSIX && (st.mode & 0o077)) {
      throw new DaemonTokenError(`Daemon token file ${file} is accessible by group/others; run: chmod 600 ${file}`);
    }
    if (POSIX && typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw new DaemonTokenError(`Daemon token file ${file} is not owned by the current user`);
    }
    const token = fs.readFileSync(fd, 'utf-8').trim();
    if (!TOKEN_RE.test(token)) {
      throw new DaemonTokenError(`Daemon token file ${file} does not hold a valid token (need >= 32 chars of [A-Za-z0-9_-])`);
    }
    return token;
  } finally {
    fs.closeSync(fd);
  }
}

/** Daemon side: read the token, creating it (dir 0700, file 0600, exclusive) when missing. */
export function ensureDaemonToken(file: string = daemonTokenPath()): string {
  try {
    return readDaemonToken(file);
  } catch (err) {
    if (!(err instanceof DaemonTokenError) || err.code !== 'ENOENT') throw err;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  try {
    fs.writeFileSync(file, `${crypto.randomBytes(32).toString('hex')}\n`, { flag: 'wx', mode: 0o600 });
  } catch (err) {
    // Another process won the race — validate whatever it wrote.
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw new DaemonTokenError(`Cannot create daemon token file ${file} (${(err as NodeJS.ErrnoException).code ?? 'error'})`);
    }
  }
  return readDaemonToken(file);
}

/** CLI side: the token, or null when it cannot be read (the daemon then answers 401). */
export function readDaemonTokenOrNull(): string | null {
  try {
    return readDaemonToken();
  } catch {
    return null;
  }
}

// ─── Signed-request protocol ─────────────────────────────────────────
// The token is never sent. Requests carry an HMAC-SHA256 signature keyed by
// the token's UTF-8 bytes; the daemon proves its identity by answering a
// nonce challenge with HMAC(key, "opencli-daemon-proof\n" + nonce).

export const AUTH_SCHEME = 'OpenCLI-HMAC';
export const MAX_CLOCK_SKEW_MS = 30_000;
/**
 * A nonce accepted at time `a` carries ts ≥ a − 30s, so it can be presented
 * again until ts + 30s ≤ a + 60s. Keeping it 61s (valid while now ≤ expiry)
 * covers that last instant with margin.
 */
export const NONCE_TTL_MS = 2 * MAX_CLOCK_SKEW_MS + 1_000;
/**
 * Signatures dated before this daemon instance started (minus this slack for
 * clock granularity / sign-then-connect delay) are rejected, so a restart does
 * not reopen the replay window of the previous instance's empty nonce cache.
 */
export const START_SLACK_MS = 2_000;
const NONCE_RE = /^[0-9a-f]{32}$/;
const SIG_RE = /^[0-9a-f]{64}$/;
const TS_RE = /^\d{1,16}$/;
export const PROOF_NONCE_RE = /^[0-9a-f]{32,128}$/;

export interface SignatureParts { ts: string; nonce: string; sig: string }

const hmacHex = (token: string, data: string): string =>
  crypto.createHmac('sha256', Buffer.from(token, 'utf-8')).update(data, 'utf-8').digest('hex');

export function sha256Hex(body: string | Uint8Array = ''): string {
  return crypto.createHash('sha256').update(body).digest('hex');
}

export function computeSignature(
  token: string, method: string, pathAndQuery: string, ts: string, nonce: string, bodySha256Hex: string,
): string {
  return hmacHex(token, [method.toUpperCase(), pathAndQuery, ts, nonce, bodySha256Hex].join('\n'));
}

export function daemonProof(token: string, nonce: string): string {
  return hmacHex(token, `opencli-daemon-proof\n${nonce}`);
}

export function newNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

// ─── Response authentication ─────────────────────────────────────────
// The client sends X-OpenCLI-Challenge; the daemon answers with
// X-OpenCLI-Proof = HMAC(key, "opencli-response\n" + challenge + "\n" +
// status + "\n" + sha256hex(body)). Prefix differs from request signatures
// (which start with an upper-case METHOD) and from the daemon identity proof.

export const CHALLENGE_HEADER = 'X-OpenCLI-Challenge';
export const PROOF_HEADER = 'X-OpenCLI-Proof';
export const CHALLENGE_RE = /^[0-9a-f]{32}$/;

export function responseProof(token: string, challenge: string, status: number, body: string | Uint8Array): string {
  return hmacHex(token, `opencli-response\n${challenge}\n${status}\n${sha256Hex(body)}`);
}

export function verifyResponseProof(
  token: string, challenge: string, status: number, body: string | Uint8Array, proof: unknown,
): boolean {
  if (typeof proof !== 'string' || !SIG_RE.test(proof)) return false;
  const expected = Buffer.from(responseProof(token, challenge, status, body), 'utf-8');
  const provided = Buffer.from(proof, 'utf-8');
  return expected.length === provided.length && crypto.timingSafeEqual(expected, provided);
}

/** Fresh ts/nonce/sig for one request. `pathAndQuery` must be exactly what goes on the wire. */
export function signParts(token: string, method: string, pathAndQuery: string, body?: string | Uint8Array): SignatureParts {
  const ts = String(Date.now());
  const nonce = newNonce();
  return { ts, nonce, sig: computeSignature(token, method, pathAndQuery, ts, nonce, sha256Hex(body ?? '')) };
}

export function authorizationHeader(parts: SignatureParts): string {
  return `${AUTH_SCHEME} ts=${parts.ts};nonce=${parts.nonce};sig=${parts.sig}`;
}

export function parseAuthorization(header: unknown): SignatureParts | null {
  if (typeof header !== 'string') return null;
  const m = /^OpenCLI-HMAC ts=([^;\s]+);nonce=([^;\s]+);sig=([^;\s]+)$/.exec(header.trim());
  return m ? { ts: m[1], nonce: m[2], sig: m[3] } : null;
}

/**
 * Replay guard for one daemon instance: remembers nonces for NONCE_TTL_MS and
 * rejects signatures dated before `notBefore` (instance start − START_SLACK_MS).
 * Fails closed when full so an attacker cannot flush a nonce out of the cache
 * and replay it inside the window.
 */
export class NonceCache {
  private readonly seen = new Map<string, number>();
  readonly notBefore: number;
  private readonly maxEntries: number;
  private readonly ttlMs: number;

  constructor(opts: { maxEntries?: number; ttlMs?: number; startedAt?: number } = {}) {
    this.maxEntries = opts.maxEntries ?? 10_000;
    this.ttlMs = opts.ttlMs ?? NONCE_TTL_MS;
    this.notBefore = (opts.startedAt ?? Date.now()) - START_SLACK_MS;
  }

  /** True when the nonce is new (and records it); false on replay or overflow. */
  claim(nonce: string, now = Date.now()): boolean {
    for (const [n, expiry] of this.seen) {
      if (expiry >= now) break; // still valid at its expiry instant; insertion order ≈ expiry order
      this.seen.delete(n);
    }
    if (this.seen.has(nonce) || this.seen.size >= this.maxEntries) return false;
    this.seen.set(nonce, now + this.ttlMs);
    return true;
  }
}

/** Validate a signature: format, clock skew, timing-safe compare, then nonce single use. */
export function verifySignature(
  token: string,
  parts: Partial<SignatureParts> | null,
  method: string,
  pathAndQuery: string,
  body: string | Uint8Array,
  nonces: NonceCache,
  now = Date.now(),
): boolean {
  if (!parts || typeof parts.ts !== 'string' || typeof parts.nonce !== 'string' || typeof parts.sig !== 'string') return false;
  if (!TS_RE.test(parts.ts) || !NONCE_RE.test(parts.nonce) || !SIG_RE.test(parts.sig)) return false;
  if (Math.abs(now - Number(parts.ts)) > MAX_CLOCK_SKEW_MS) return false;
  if (Number(parts.ts) < nonces.notBefore) return false; // signed for an earlier daemon instance
  const expected = Buffer.from(computeSignature(token, method, pathAndQuery, parts.ts, parts.nonce, sha256Hex(body)), 'utf-8');
  const provided = Buffer.from(parts.sig, 'utf-8');
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) return false;
  return nonces.claim(parts.nonce, now);
}

/** HTTP request (body already read). Signs METHOD + raw request target. */
export function isAuthorizedRequest(req: IncomingMessage, body: string | Uint8Array, token: string, nonces: NonceCache): boolean {
  return verifySignature(token, parseAuthorization(req.headers['authorization']), req.method ?? '', req.url ?? '/', body, nonces);
}

/**
 * WebSocket `/ext` upgrade: Origin must be absent or chrome-extension://, and
 * the query must carry ts/nonce/sig over ("GET", "/ext", empty body).
 */
export function isAuthorizedExtUpgrade(req: IncomingMessage, token: string, nonces: NonceCache): boolean {
  const origin = req.headers['origin'];
  if (origin && !origin.startsWith('chrome-extension://')) return false;
  let params: URLSearchParams;
  try {
    params = new URL(req.url ?? '/', 'http://127.0.0.1').searchParams;
  } catch {
    return false;
  }
  const parts = { ts: params.get('ts') ?? undefined, nonce: params.get('nonce') ?? undefined, sig: params.get('sig') ?? undefined };
  return verifySignature(token, parts, 'GET', '/ext', '', nonces);
}
