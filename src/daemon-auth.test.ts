import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import WebSocket, { WebSocketServer } from 'ws';
import {
  DaemonTokenError,
  ensureDaemonToken,
  isAuthorizedExtUpgrade,
  isAuthorizedRequest,
  readDaemonToken,
  readDaemonTokenOrNull,
  tokensMatch,
} from './daemon-auth.js';

const posix = process.platform !== 'win32';
let dir: string;

beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opencli-auth-')); });
afterAll(() => { fs.rmSync(dir, { recursive: true, force: true }); });
afterEach(() => { delete process.env.OPENCLI_DAEMON_TOKEN_FILE; });

describe('daemon token file', () => {
  it('creates a 64-hex token with 0700 dir / 0600 file and reads it back', () => {
    const file = path.join(dir, 'fresh', 'daemon-token');
    const token = ensureDaemonToken(file);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    expect(ensureDaemonToken(file)).toBe(token);
    if (posix) {
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
    }
  });

  it('honours OPENCLI_DAEMON_TOKEN_FILE; the CLI reader returns null when it is missing', () => {
    process.env.OPENCLI_DAEMON_TOKEN_FILE = path.join(dir, 'env', 'tok');
    expect(readDaemonTokenOrNull()).toBeNull();
    const token = ensureDaemonToken();
    expect(readDaemonTokenOrNull()).toBe(token);
  });

  it.runIf(posix)('rejects a group/other-readable file', () => {
    const file = path.join(dir, 'loose');
    fs.writeFileSync(file, 'b'.repeat(64), { mode: 0o644 });
    fs.chmodSync(file, 0o644);
    expect(() => ensureDaemonToken(file)).toThrow(/group\/others/);
  });

  it.runIf(posix)('rejects a symbolic link', () => {
    const target = path.join(dir, 'target');
    fs.writeFileSync(target, 'c'.repeat(64), { mode: 0o600 });
    const link = path.join(dir, 'link');
    fs.symlinkSync(target, link);
    expect(() => ensureDaemonToken(link)).toThrow(/symbolic link/);
  });

  it('rejects a directory', () => {
    const d = path.join(dir, 'is-dir');
    fs.mkdirSync(d);
    expect(() => readDaemonToken(d)).toThrow(/not a regular file/);
  });

  it('rejects a short or malformed token without echoing it', () => {
    const file = path.join(dir, 'short');
    fs.writeFileSync(file, 'tooShortSecret', { mode: 0o600 });
    expect(() => ensureDaemonToken(file)).toThrow(DaemonTokenError);
    try { ensureDaemonToken(file); } catch (err) { expect(String(err)).not.toContain('tooShortSecret'); }
    fs.writeFileSync(file, `${'d'.repeat(40)} bad`, { mode: 0o600 });
    expect(() => readDaemonToken(file)).toThrow(/valid token/);
  });

  it('accepts surrounding whitespace', () => {
    const file = path.join(dir, 'ws');
    fs.writeFileSync(file, `  ${'e'.repeat(32)}\n`, { mode: 0o600 });
    expect(readDaemonToken(file)).toBe('e'.repeat(32));
  });
});

describe('tokensMatch', () => {
  it('requires exact equal-length match', () => {
    expect(tokensMatch('x'.repeat(32), 'x'.repeat(32))).toBe(true);
    expect(tokensMatch('x'.repeat(32), 'x'.repeat(31))).toBe(false);
    expect(tokensMatch('x'.repeat(32), 'y'.repeat(32))).toBe(false);
    expect(tokensMatch('x'.repeat(32), undefined)).toBe(false);
  });
});

/**
 * Real HTTP + WS server gated exactly the way src/daemon.ts gates it:
 * /ping open, everything else Bearer, /ext upgrade via verifyClient.
 */
describe('daemon HTTP / WebSocket gate', () => {
  const TOKEN = 'f'.repeat(64);
  let server: Server;
  let wss: WebSocketServer;
  let base: string;

  beforeAll(async () => {
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const pathname = (req.url ?? '/').split('?')[0];
      const send = (status: number, body: unknown) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method === 'GET' && pathname === '/ping') return send(200, { ok: true });
      if (!isAuthorizedRequest(req, TOKEN)) return send(401, { ok: false, error: 'Unauthorized' });
      return send(200, { ok: true, reached: pathname });
    });
    wss = new WebSocketServer({ server, path: '/ext', verifyClient: ({ req }: { req: IncomingMessage }) => isAuthorizedExtUpgrade(req, TOKEN) });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    wss.close();
    await new Promise((resolve) => server.close(resolve));
  });

  const get = (p: string, headers: Record<string, string> = {}) => fetch(`http://${base}${p}`, { headers: { 'X-OpenCLI': '1', ...headers } });

  it('/ping passes without a token and returns only { ok: true }', async () => {
    const res = await fetch(`http://${base}/ping`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('401 without a token', async () => {
    const res = await get('/status');
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: 'Unauthorized' });
  });

  it('401 with a wrong or wrong-length token', async () => {
    expect((await get('/status', { Authorization: `Bearer ${'0'.repeat(64)}` })).status).toBe(401);
    expect((await get('/status', { Authorization: 'Bearer short' })).status).toBe(401);
    expect((await get('/status', { Authorization: TOKEN })).status).toBe(401);
  });

  it('passes with the right token', async () => {
    const res = await get('/status', { Authorization: `Bearer ${TOKEN}` });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, reached: '/status' });
  });

  const dial = (query: string, origin?: string) => new Promise<'open' | 'rejected'>((resolve) => {
    const ws = new WebSocket(`ws://${base}/ext${query}`, origin ? { headers: { origin } } : {});
    ws.once('open', () => { ws.close(); resolve('open'); });
    ws.once('error', () => resolve('rejected'));
  });

  it('rejects /ext upgrade without or with a wrong token', async () => {
    expect(await dial('')).toBe('rejected');
    expect(await dial(`?token=${'0'.repeat(64)}`)).toBe('rejected');
  });

  it('accepts /ext with the token from no-origin or chrome-extension://, rejects web origins', async () => {
    expect(await dial(`?token=${TOKEN}`)).toBe('open');
    expect(await dial(`?token=${TOKEN}`, 'chrome-extension://abc')).toBe('open');
    expect(await dial(`?token=${TOKEN}`, 'https://evil.example')).toBe('rejected');
  });
});
