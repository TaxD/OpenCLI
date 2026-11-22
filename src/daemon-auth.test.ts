import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import WebSocket, { WebSocketServer } from 'ws';
import { createHash, createHmac } from 'node:crypto';
import {
  DaemonTokenError,
  NonceCache,
  authorizationHeader,
  daemonProof,
  wsProof,
  ensureDaemonToken,
  isAuthorizedExtUpgrade,
  isAuthorizedRequest,
  readDaemonToken,
  readDaemonTokenOrNull,
  responseProof,
  signParts,
  verifyResponseProof,
  verifySignature,
  MAX_CLOCK_SKEW_MS,
  NONCE_TTL_MS,
  START_SLACK_MS,
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

/** Independent reference implementation of the wire protocol. */
const refSig = (token: string, method: string, target: string, ts: string, nonce: string, body = '') =>
  createHmac('sha256', Buffer.from(token, 'utf-8'))
    .update([method, target, ts, nonce, createHash('sha256').update(body).digest('hex')].join('\n'))
    .digest('hex');

describe('signature primitives', () => {
  it('signParts / daemonProof match the documented formulas', () => {
    const token = 'k'.repeat(64);
    const p = signParts(token, 'post', '/command', '{"a":1}');
    expect(p.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(Math.abs(Date.now() - Number(p.ts))).toBeLessThan(1000);
    expect(p.sig).toBe(refSig(token, 'POST', '/command', p.ts, p.nonce, '{"a":1}'));
    const nonce = 'ab'.repeat(16);
    expect(daemonProof(token, nonce)).toBe(createHmac('sha256', token).update(`opencli-daemon-proof\n${nonce}`).digest('hex'));
    const sig = 'cd'.repeat(32);
    expect(wsProof(token, nonce, sig)).toBe(createHmac('sha256', token).update(`opencli-ws-proof\n${nonce}\n${sig}`).digest('hex'));
    expect(wsProof(token, nonce, sig)).not.toBe(daemonProof(token, nonce));
    expect(wsProof(token, nonce, sig)).not.toBe(wsProof(token, nonce, 'ef'.repeat(32)));
  });

  it('response proof covers challenge, status and exact body bytes', () => {
    const token = 'k'.repeat(64);
    const challenge = 'cd'.repeat(16);
    const body = '{"ok":true,"pid":1}';
    const proof = responseProof(token, challenge, 200, body);
    expect(proof).toBe(createHmac('sha256', token)
      .update(`opencli-response\n${challenge}\n200\n${createHash('sha256').update(body).digest('hex')}`).digest('hex'));
    expect(verifyResponseProof(token, challenge, 200, Buffer.from(body), proof)).toBe(true);
    expect(verifyResponseProof(token, challenge, 201, body, proof)).toBe(false);
    expect(verifyResponseProof(token, challenge, 200, body.replace('1', '2'), proof)).toBe(false);
    expect(verifyResponseProof(token, 'ef'.repeat(16), 200, body, proof)).toBe(false);
    expect(verifyResponseProof('z'.repeat(64), challenge, 200, body, proof)).toBe(false);
    expect(verifyResponseProof(token, challenge, 200, body, proof.slice(1))).toBe(false);
    expect(verifyResponseProof(token, challenge, 200, body, null)).toBe(false);
  });

  it('NonceCache rejects replays, forgets after the TTL, and fails closed when full', () => {
    const cache = new NonceCache({ maxEntries: 2, ttlMs: 60_000, startedAt: 0 });
    expect(cache.claim('a', 0)).toBe(true);
    expect(cache.claim('a', 1)).toBe(false);
    expect(cache.claim('b', 2)).toBe(true);
    expect(cache.claim('c', 3)).toBe(false); // full
    expect(cache.claim('a', 60_001)).toBe(true); // expired
  });
});

describe('replay boundaries', () => {
  const token = 'r'.repeat(64);
  const signed = (ts: number, nonce = 'ab'.repeat(16)) =>
    ({ ts: String(ts), nonce, sig: refSig(token, 'GET', '/status', String(ts), nonce) });
  const check = (parts: ReturnType<typeof signed>, cache: NonceCache, now: number) =>
    verifySignature(token, parts, 'GET', '/status', '', cache, now);

  it('keeps nonces strictly longer than any signature stays valid', () => {
    expect(NONCE_TTL_MS).toBeGreaterThan(2 * MAX_CLOCK_SKEW_MS);
  });

  it('rejects a replay at the last instant of the ±30s window (accepted at the first instant)', () => {
    const T = 1_000_000_000;
    const cache = new NonceCache({ startedAt: 0 });
    const parts = signed(T);
    expect(check(parts, cache, T - MAX_CLOCK_SKEW_MS)).toBe(true);   // earliest acceptance
    expect(check(parts, cache, T + MAX_CLOCK_SKEW_MS)).toBe(false);  // latest instant the ts is still in-window
    expect(check(parts, cache, T + MAX_CLOCK_SKEW_MS + 1)).toBe(false); // out of window anyway
  });

  it('treats a nonce as remembered up to and including its expiry instant', () => {
    const cache = new NonceCache({ maxEntries: 10, ttlMs: 1_000, startedAt: 0 });
    expect(cache.claim('n', 0)).toBe(true);
    expect(cache.claim('n', 1_000)).toBe(false);
    expect(cache.claim('n', 1_001)).toBe(true);
  });

  it('rejects signatures dated before the daemon instance started (beyond the slack)', () => {
    const S = 2_000_000_000;
    const cache = new NonceCache({ startedAt: S });
    expect(check(signed(S - START_SLACK_MS - 1, '01'.repeat(16)), cache, S)).toBe(false);
    expect(check(signed(S - START_SLACK_MS, '02'.repeat(16)), cache, S)).toBe(true); // within slack: accepted (documented residual)
    expect(check(signed(S + 10, '03'.repeat(16)), cache, S + 20)).toBe(true);
  });

  it('a restarted daemon does not accept a signature the previous instance saw', () => {
    const T = 3_000_000_000;
    const parts = signed(T);
    const before = new NonceCache({ startedAt: T - 60_000 });
    expect(check(parts, before, T)).toBe(true);
    const restarted = new NonceCache({ startedAt: T + START_SLACK_MS + 1 }); // fresh, empty cache
    expect(check(parts, restarted, T + START_SLACK_MS + 1)).toBe(false);
  });
});

/**
 * Real HTTP + WS server gated exactly the way src/daemon.ts gates it:
 * /ping open, body read first, everything else signed, /ext via verifyClient.
 * (tests/e2e/daemon-transport.test.ts repeats the checks against the real daemon.)
 */
describe('daemon HTTP / WebSocket gate', () => {
  const TOKEN = 'f'.repeat(64);
  let server: Server;
  let wss: WebSocketServer;
  let base: string;

  beforeAll(async () => {
    const nonces = new NonceCache();
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const pathname = (req.url ?? '/').split('?')[0];
        const send = (status: number, body: unknown) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
        if (req.method === 'GET' && pathname === '/ping') return send(200, { ok: true });
        if (!isAuthorizedRequest(req, Buffer.concat(chunks), TOKEN, nonces)) return send(401, { ok: false, error: 'Unauthorized' });
        return send(200, { ok: true, reached: req.url });
      });
    });
    wss = new WebSocketServer({ server, path: '/ext', verifyClient: ({ req }: { req: IncomingMessage }) => isAuthorizedExtUpgrade(req, TOKEN, nonces) });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    wss.close();
    await new Promise((resolve) => server.close(resolve));
  });

  const call = (target: string, opts: { method?: string; body?: string; auth?: string } = {}) => fetch(`http://${base}${target}`, {
    method: opts.method ?? 'GET',
    body: opts.body,
    headers: { 'X-OpenCLI': '1', ...(opts.auth ? { Authorization: opts.auth } : {}) },
  });
  const header = (ts: string, nonce: string, sig: string) => authorizationHeader({ ts, nonce, sig });
  const fresh = () => ({ ts: String(Date.now()), nonce: createHash('md5').update(Math.random().toString()).digest('hex') });

  it('/ping passes without a signature', async () => {
    const res = await fetch(`http://${base}/ping`);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('401 without a signature, and with a raw token as Bearer', async () => {
    const res = await call('/status');
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: 'Unauthorized' });
    expect((await call('/status', { auth: `Bearer ${TOKEN}` })).status).toBe(401);
  });

  it('passes with a correct signature over method, path+query and body', async () => {
    const { ts, nonce } = fresh();
    const body = '{"id":"1"}';
    const res = await call('/command?x=1', { method: 'POST', body, auth: header(ts, nonce, refSig(TOKEN, 'POST', '/command?x=1', ts, nonce, body)) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, reached: '/command?x=1' });
  });

  it('401 when the clock is more than 30s off', async () => {
    for (const skew of [-31_000, 31_000]) {
      const ts = String(Date.now() + skew);
      const { nonce } = fresh();
      expect((await call('/status', { auth: header(ts, nonce, refSig(TOKEN, 'GET', '/status', ts, nonce)) })).status).toBe(401);
    }
  });

  it('401 when a nonce is reused', async () => {
    const { ts, nonce } = fresh();
    const auth = header(ts, nonce, refSig(TOKEN, 'GET', '/status', ts, nonce));
    expect((await call('/status', { auth })).status).toBe(200);
    expect((await call('/status', { auth })).status).toBe(401);
  });

  it('401 when the path, query, method or body differ from what was signed, or the key is wrong', async () => {
    const body = '{"id":"1"}';
    const cases: Array<[string, { method?: string; body?: string }, (ts: string, n: string) => string]> = [
      ['/logs', {}, (ts, n) => refSig(TOKEN, 'GET', '/status', ts, n)],
      ['/status?contextId=b', {}, (ts, n) => refSig(TOKEN, 'GET', '/status?contextId=a', ts, n)],
      ['/status', { method: 'DELETE' }, (ts, n) => refSig(TOKEN, 'GET', '/status', ts, n)],
      ['/command', { method: 'POST', body: '{"id":"2"}' }, (ts, n) => refSig(TOKEN, 'POST', '/command', ts, n, body)],
      ['/status', {}, (ts, n) => refSig('0'.repeat(64), 'GET', '/status', ts, n)],
    ];
    for (const [target, opts, sign] of cases) {
      const { ts, nonce } = fresh();
      expect((await call(target, { ...opts, auth: header(ts, nonce, sign(ts, nonce)) })).status, target).toBe(401);
    }
  });

  const dial = (query: string, origin?: string) => new Promise<'open' | 'rejected'>((resolve) => {
    const ws = new WebSocket(`ws://${base}/ext${query}`, origin ? { headers: { origin } } : {});
    ws.once('open', () => { ws.close(); resolve('open'); });
    ws.once('error', () => resolve('rejected'));
  });
  const signedQuery = (token = TOKEN) => {
    const { ts, nonce } = fresh();
    return `?ts=${ts}&nonce=${nonce}&sig=${refSig(token, 'GET', '/ext', ts, nonce)}`;
  };

  it('rejects /ext upgrade without a signature, with a wrong key, or with ?token=', async () => {
    expect(await dial('')).toBe('rejected');
    expect(await dial(signedQuery('0'.repeat(64)))).toBe('rejected');
    expect(await dial(`?token=${TOKEN}`)).toBe('rejected');
  });

  it('accepts a signed /ext from no-origin or chrome-extension://, rejects web origins and replays', async () => {
    expect(await dial(signedQuery())).toBe('open');
    expect(await dial(signedQuery(), 'chrome-extension://abc')).toBe('open');
    expect(await dial(signedQuery(), 'https://evil.example')).toBe('rejected');
    const q = signedQuery();
    expect(await dial(q)).toBe('open');
    expect(await dial(q)).toBe('rejected');
  });
});
