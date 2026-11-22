/**
 * Shared-secret authentication between the CLI, the daemon and the Browser
 * Bridge extension.
 *
 * The token lives in a 0600 file (default ~/.opencli/daemon-token, override
 * with OPENCLI_DAEMON_TOKEN_FILE). The daemon creates it on first start; the
 * CLI only reads it. Token values never appear in logs or error messages.
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

export function tokensMatch(expected: string, provided: unknown): boolean {
  if (typeof provided !== 'string') return false;
  const a = Buffer.from(expected, 'utf-8');
  const b = Buffer.from(provided, 'utf-8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** HTTP: `Authorization: Bearer <token>`. */
export function isAuthorizedRequest(req: IncomingMessage, token: string): boolean {
  const header = req.headers['authorization'];
  if (typeof header !== 'string') return false;
  const match = /^Bearer ([^\s]+)$/.exec(header.trim());
  return !!match && tokensMatch(token, match[1]);
}

/**
 * WebSocket `/ext` upgrade: Origin must be absent or chrome-extension://, and
 * `?token=<token>` must match (browser WebSocket cannot set headers).
 */
export function isAuthorizedExtUpgrade(req: IncomingMessage, token: string): boolean {
  const origin = req.headers['origin'];
  if (origin && !origin.startsWith('chrome-extension://')) return false;
  let provided: string | null;
  try {
    provided = new URL(req.url ?? '/', 'http://127.0.0.1').searchParams.get('token');
  } catch {
    return false;
  }
  return tokensMatch(token, provided);
}
