import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  BrowserCommandError,
  clearDaemonRunContext,
  fetchDaemonStatus,
  getDaemonHealth,
  isUnknownOutcomeError,
  requestDaemonShutdown,
  sendCommand,
  setDaemonCommandTimeoutSeconds,
  setDaemonRunContext,
} from './daemon-client.js';
import { BrowserConnectError, SessionBusyError } from '../errors.js';
import { createHash, createHmac } from 'node:crypto';
import * as fs from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as daemonLifecycle from './daemon-lifecycle.js';
import { UnauthenticatedDaemonError, requestDaemon } from './daemon-transport.js';
import { responseProof } from '../daemon-auth.js';

const realFetch = globalThis.fetch;
const TEST_TOKEN = 't'.repeat(64);
const SIGNED = /^OpenCLI-HMAC ts=\d+;nonce=[0-9a-f]{32};sig=[0-9a-f]{64}$/;

/** Point the CLI at a throwaway 0600 token file instead of ~/.opencli/daemon-token. */
function useTestTokenFile(): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opencli-client-'));
  const file = path.join(dir, 'daemon-token');
  fs.writeFileSync(file, TEST_TOKEN, { mode: 0o600 });
  vi.stubEnv('OPENCLI_DAEMON_TOKEN_FILE', file);
}

/**
 * Tests script the daemon by mocking `daemonFetch` with plain `{ ok, status,
 * json }` objects; the global fetch turns them into real Responses carrying a
 * valid X-OpenCLI-Proof for the request's challenge, as the real daemon does.
 */
let daemonFetch: ReturnType<typeof vi.fn<(url: string, init?: RequestInit) => Promise<any>>>;

async function asSignedDaemonResponse(fake: any, init?: RequestInit, token = TEST_TOKEN): Promise<Response> {
  const challenge = (init?.headers as Record<string, string> | undefined)?.['X-OpenCLI-Challenge'] ?? '';
  const status = fake?.status ?? (fake?.ok === false ? 500 : 200);
  const body = typeof fake?.json === 'function' ? JSON.stringify(await fake.json()) : '';
  return new Response(body || null, { status, headers: { 'X-OpenCLI-Proof': responseProof(token, challenge, status, body) } });
}

describe('daemon-client', () => {
  beforeEach(() => {
    daemonFetch = vi.fn();
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => asSignedDaemonResponse(await daemonFetch(url, init), init)));
    useTestTokenFile();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    setDaemonRunContext(null);
  });

  it('fetchDaemonStatus sends the shared status request and returns parsed data', async () => {
    const status = {
      ok: true,
      pid: 123,
      uptime: 10,
      extensionConnected: true,
      extensionVersion: '1.2.3',
      pending: 0,
      memoryMB: 32,
      port: 19825,
    };
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(status),
    } as Response);

    await expect(fetchDaemonStatus()).resolves.toEqual(status);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/status$/),
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-OpenCLI': '1', Authorization: expect.stringMatching(SIGNED) }),
      }),
    );
  });

  it('signs method, exact path+query and body hash with HMAC and never sends the token itself', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValue({ ok: true, json: () => Promise.resolve({ id: 'x', ok: true }) } as Response);
    const body = JSON.stringify({ id: 'x', action: 'lease-release' });
    await requestDaemon('/status?contextId=a b&preferredContextId=c', { timeout: 1000 });
    await requestDaemon('/command', { method: 'POST', body, timeout: 1000 });

    const check = (call: unknown[], method: string, target: string, sentBody: string) => {
      const [url, init] = call as [string, RequestInit];
      const u = new URL(url);
      expect(u.pathname + u.search).toBe(target);
      const auth = (init.headers as Record<string, string>).Authorization;
      const [, ts, nonce, sig] = /^OpenCLI-HMAC ts=(\d+);nonce=([0-9a-f]{32});sig=([0-9a-f]{64})$/.exec(auth)!;
      const expected = createHmac('sha256', TEST_TOKEN)
        .update([method, target, ts, nonce, createHash('sha256').update(sentBody).digest('hex')].join('\n'))
        .digest('hex');
      expect(sig).toBe(expected);
    };
    check(fetchMock.mock.calls[0], 'GET', '/status?contextId=a%20b&preferredContextId=c', '');
    check(fetchMock.mock.calls[1], 'POST', '/command', body);
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain(TEST_TOKEN);
  });

  it('omits Authorization when the token file is missing and cannot trust the reply', async () => {
    vi.stubEnv('OPENCLI_DAEMON_TOKEN_FILE', path.join(os.tmpdir(), 'opencli-no-such-dir', 'daemon-token'));
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValue({ ok: true } as Response);
    await expect(requestDaemonShutdown()).rejects.toBeInstanceOf(UnauthenticatedDaemonError);
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers).not.toHaveProperty('Authorization');
    expect(headers['X-OpenCLI-Challenge']).toMatch(/^[0-9a-f]{32}$/);
  });

  describe('response authentication', () => {
    const forgedStatus = {
      ok: true, pid: 4242, uptime: 1, daemonVersion: '0.0.1', extensionConnected: true,
      extensionVersion: '9.9.9', pending: 0, memoryMB: 1, port: 19825,
    };
    /** An impostor on the port: answers with a forged status and the given proof header. */
    const impostor = (proof?: (init?: RequestInit) => string, body = JSON.stringify(forgedStatus), status = 200) =>
      vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) =>
        new Response(body, { status, headers: proof ? { 'X-OpenCLI-Proof': proof(init) } : {} })));
    const challengeOf = (init?: RequestInit) => (init?.headers as Record<string, string>)['X-OpenCLI-Challenge'];

    it.each([
      ['no proof', undefined],
      ['a garbage proof', () => 'a'.repeat(64)],
      ['a proof made with another key', (init?: RequestInit) => responseProof('z'.repeat(64), challengeOf(init), 200, JSON.stringify(forgedStatus))],
      ['a proof for a different challenge', () => responseProof(TEST_TOKEN, '0'.repeat(32), 200, JSON.stringify(forgedStatus))],
    ])('ignores a status with %s: no field used, no signal, no spawn, no shutdown', async (_label, proof) => {
      impostor(proof as ((init?: RequestInit) => string) | undefined);
      const killSpy = vi.spyOn(process, 'kill').mockImplementation(() => true);
      const spawnSpy = vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'spawnDaemonProcess').mockImplementation(() => { throw new Error('spawned'); });
      const shutdownSpy = vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'requestDaemonShutdown');

      await expect(fetchDaemonStatus()).rejects.toBeInstanceOf(UnauthenticatedDaemonError);
      await expect(getDaemonHealth()).rejects.toBeInstanceOf(UnauthenticatedDaemonError);
      // The forged daemonVersion 0.0.1 would trigger stale replacement if it were trusted.
      const err = await daemonLifecycle.ensureBrowserBridgeReady({ timeoutSeconds: 1, verbose: false }).catch((e) => e);
      expect(err).toBeInstanceOf(UnauthenticatedDaemonError);
      expect(String(err.message) + String(err.hint)).not.toMatch(/4242|0\.0\.1|9\.9\.9/);
      await expect(sendCommand('exec', { code: '1' })).rejects.toBeInstanceOf(UnauthenticatedDaemonError);

      expect(killSpy).not.toHaveBeenCalled();
      expect(spawnSpy).not.toHaveBeenCalled();
      expect(shutdownSpy).not.toHaveBeenCalled();
    });

    it.each([302, 307, 308])('never follows a %i from the daemon port: one request, unauthenticated error, no spawn/kill', async (code) => {
      const hits: string[] = [];
      const server = createServer((req, res) => {
        hits.push(`${req.method} ${req.url}`);
        if (req.url === '/stolen') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{}'); return; }
        res.writeHead(code, { Location: `http://127.0.0.1:${(server.address() as AddressInfo).port}/stolen` });
        res.end();
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const port = (server.address() as AddressInfo).port;
      // Real undici fetch, retargeted from the fixed daemon port to the test server.
      vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) =>
        realFetch(String(url).replace(':19825', `:${port}`), init)));
      const killSpy = vi.spyOn(process, 'kill').mockImplementation(() => true);
      const spawnSpy = vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'spawnDaemonProcess').mockImplementation(() => { throw new Error('spawned'); });
      try {
        await expect(fetchDaemonStatus()).rejects.toBeInstanceOf(UnauthenticatedDaemonError);
        await expect(requestDaemon('/command', { method: 'POST', body: '{"id":"x"}' })).rejects.toThrow(/redirect/);
        await expect(daemonLifecycle.ensureBrowserBridgeReady({ timeoutSeconds: 1, verbose: false })).rejects.toBeInstanceOf(UnauthenticatedDaemonError);
        expect(hits).toEqual(['GET /status', 'POST /command', 'GET /status']);
        expect(killSpy).not.toHaveBeenCalled();
        expect(spawnSpy).not.toHaveBeenCalled();
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    });

    it('accepts only the exact status code and body the proof covers', async () => {
      const body = JSON.stringify(forgedStatus);
      impostor((init) => responseProof(TEST_TOKEN, challengeOf(init), 200, body), body);
      await expect(fetchDaemonStatus()).resolves.toEqual(forgedStatus);

      impostor((init) => responseProof(TEST_TOKEN, challengeOf(init), 200, body), body.replace('4242', '4243'));
      await expect(fetchDaemonStatus()).rejects.toBeInstanceOf(UnauthenticatedDaemonError);

      impostor((init) => responseProof(TEST_TOKEN, challengeOf(init), 200, body), body, 201);
      await expect(fetchDaemonStatus()).rejects.toBeInstanceOf(UnauthenticatedDaemonError);
    });

    it('never calls process.kill with a pid from a daemon response, even when a stale daemon refuses to stop', async () => {
      const body = JSON.stringify(forgedStatus);
      impostor((init) => responseProof(TEST_TOKEN, challengeOf(init), 200, body), body);
      const killSpy = vi.spyOn(process, 'kill').mockImplementation(() => true);
      vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'requestDaemonShutdown').mockResolvedValue(false);
      const spawnSpy = vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'spawnDaemonProcess');
      await expect(daemonLifecycle.ensureBrowserBridgeReady({ timeoutSeconds: 1, verbose: false }))
        .rejects.toThrow('Stale daemon could not be replaced');
      expect(killSpy).not.toHaveBeenCalled();
      expect(spawnSpy).not.toHaveBeenCalled();
    });
  });

  describe('OPENCLI_DAEMON_MANAGED=1', () => {
    beforeEach(() => { vi.stubEnv('OPENCLI_DAEMON_MANAGED', '1'); });

    it('fails fast without spawning when no daemon is running', async () => {
      daemonFetch.mockRejectedValue(new TypeError('fetch failed'));
      const spawnSpy = vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'spawnDaemonProcess');
      await expect(daemonLifecycle.ensureBrowserBridgeReady({ timeoutSeconds: 1, verbose: false }))
        .rejects.toThrow(/OPENCLI_DAEMON_MANAGED=1/);
      expect(spawnSpy).not.toHaveBeenCalled();
      expect(() => daemonLifecycle.spawnDaemonProcess()).toThrow(/OPENCLI_DAEMON_MANAGED=1/);
    });

    it('does not restart a stale daemon or send /shutdown', async () => {
      daemonFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve({
        ok: true, pid: 1, uptime: 1, daemonVersion: '0.0.1', extensionConnected: true, pending: 0, memoryMB: 1, port: 19825,
      }) });
      const spawnSpy = vi.spyOn(daemonLifecycle.daemonLifecycleHooks, 'spawnDaemonProcess');
      const killSpy = vi.spyOn(process, 'kill').mockImplementation(() => true);
      const health = await daemonLifecycle.ensureBrowserBridgeReady({ timeoutSeconds: 1, verbose: false });
      expect(health.state).toBe('ready');
      expect(daemonFetch.mock.calls.every(([url]) => !String(url).endsWith('/shutdown'))).toBe(true);
      expect(spawnSpy).not.toHaveBeenCalled();
      expect(killSpy).not.toHaveBeenCalled();

      await expect(requestDaemonShutdown()).rejects.toThrow(/OPENCLI_DAEMON_MANAGED=1/);
      await expect(daemonLifecycle.restartDaemon()).rejects.toThrow(/OPENCLI_DAEMON_MANAGED=1/);
      expect(daemonFetch.mock.calls.every(([url]) => !String(url).endsWith('/shutdown'))).toBe(true);
    });
  });

  it('fetchDaemonStatus surfaces a 401 as a BrowserConnectError instead of "stopped"', async () => {
    daemonFetch.mockResolvedValue({ ok: false, status: 401 } as Response);
    const err = await fetchDaemonStatus().catch((e) => e);
    expect(err).toBeInstanceOf(BrowserConnectError);
    expect(String(err.message) + String(err.hint)).not.toContain(TEST_TOKEN);
  });

  it('fetchDaemonStatus returns null on network failure', async () => {
    daemonFetch.mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(fetchDaemonStatus()).resolves.toBeNull();
  });

  it('requestDaemonShutdown POSTs to the shared shutdown endpoint', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValue({ ok: true } as Response);

    await expect(requestDaemonShutdown()).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/shutdown$/),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-OpenCLI': '1', Authorization: expect.stringMatching(SIGNED) }),
      }),
    );
  });

  it('getDaemonHealth returns stopped when daemon is not reachable', async () => {
    daemonFetch.mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(getDaemonHealth()).resolves.toEqual({ state: 'stopped', status: null });
  });

  it('getDaemonHealth returns no-extension when daemon is running but extension disconnected', async () => {
    const status = {
      ok: true,
      pid: 123,
      uptime: 10,
      extensionConnected: false,
      pending: 0,
      memoryMB: 16,
      port: 19825,
    };
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(status),
    } as Response);

    await expect(getDaemonHealth()).resolves.toEqual({ state: 'no-extension', status });
  });

  it('getDaemonHealth returns ready when daemon and extension are both connected', async () => {
    const status = {
      ok: true,
      pid: 123,
      uptime: 10,
      extensionConnected: true,
      extensionVersion: '1.2.3',
      pending: 0,
      memoryMB: 32,
      port: 19825,
    };
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(status),
    } as Response);

    await expect(getDaemonHealth()).resolves.toEqual({ state: 'ready', status });
  });

  it('getDaemonHealth returns profile-required when multiple profiles are connected without a selection', async () => {
    const status = {
      ok: true,
      pid: 123,
      uptime: 10,
      extensionConnected: false,
      profileRequired: true,
      profiles: [
        { contextId: 'work', extensionConnected: true, pending: 0 },
        { contextId: 'personal', extensionConnected: true, pending: 0 },
      ],
      pending: 0,
      memoryMB: 32,
      port: 19825,
    };
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(status),
    } as Response);

    await expect(getDaemonHealth()).resolves.toEqual({ state: 'profile-required', status });
  });

  it('fetchDaemonStatus includes contextId in the status query', async () => {
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        ok: true,
        pid: 1,
        uptime: 0,
        extensionConnected: true,
        pending: 0,
        memoryMB: 1,
        port: 19825,
      }),
    } as Response);

    await fetchDaemonStatus({ contextId: 'work' });

    expect(daemonFetch.mock.calls[0][0]).toMatch(/\/status\?contextId=work$/);
  });

  it('fetchDaemonStatus joins contextId and preferredContextId in the status query', async () => {
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        ok: true,
        pid: 1,
        uptime: 0,
        extensionConnected: true,
        pending: 0,
        memoryMB: 1,
        port: 19825,
      }),
    } as Response);

    await fetchDaemonStatus({ preferredContextId: 'zvypsyje' });
    await fetchDaemonStatus({ contextId: 'work', preferredContextId: 'zvypsyje' });

    expect(daemonFetch.mock.calls[0][0]).toMatch(/\/status\?preferredContextId=zvypsyje$/);
    expect(daemonFetch.mock.calls[1][0]).toMatch(/\/status\?contextId=work&preferredContextId=zvypsyje$/);
  });

  it('rejects OPENCLI_DAEMON_PORT so CLI and extension cannot split bridge ports', async () => {
    vi.resetModules();
    vi.stubEnv('OPENCLI_DAEMON_PORT', '19999');
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        ok: true,
        pid: 1,
        uptime: 0,
        extensionConnected: true,
        pending: 0,
        memoryMB: 1,
        port: 19825,
      }),
    } as Response);

    const freshClient = await import('./daemon-client.js');
    await expect(freshClient.fetchDaemonStatus()).rejects.toThrow('OPENCLI_DAEMON_PORT is no longer supported');

    expect(daemonFetch).not.toHaveBeenCalled();
  });

  it('tolerates OPENCLI_DAEMON_PORT when it equals the default port (launchers inject it, #2068)', async () => {
    vi.resetModules();
    vi.stubEnv('OPENCLI_DAEMON_PORT', '19825');
    const status = {
      ok: true,
      pid: 1,
      uptime: 0,
      extensionConnected: true,
      pending: 0,
      memoryMB: 1,
      port: 19825,
    };
    daemonFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(status),
    } as Response);

    const freshClient = await import('./daemon-client.js');
    await expect(freshClient.fetchDaemonStatus()).resolves.toEqual(status);
  });

  it('sendCommand includes the current pid in generated command ids', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_763_000_000_000);
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await expect(sendCommand('exec', { code: '1 + 1' })).resolves.toBe('ok');
    await expect(sendCommand('exec', { code: '2 + 2' })).resolves.toBe('ok');

    const ids = daemonFetch.mock.calls.map(([, init]) => {
      const body = JSON.parse(String(init?.body)) as { id: string };
      return body.id;
    });

    expect(ids).toHaveLength(2);
    expect(ids[0]).toMatch(new RegExp(`^cmd_${process.pid}_1763000000000_\\d+$`));
    expect(ids[1]).toMatch(new RegExp(`^cmd_${process.pid}_1763000000000_\\d+$`));
    expect(ids[0]).not.toBe(ids[1]);
  });

  it('attaches the run context (runId/command/access) to every command as a lease heartbeat', async () => {
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);
    setDaemonRunContext({ runId: 'run_4242_1_a', command: 'chatgpt ask', access: 'write' });

    await sendCommand('exec', { code: '1 + 1', surface: 'adapter', session: 'site:chatgpt', siteSession: 'persistent' });
    await sendCommand('exec', { code: '2 + 2', surface: 'adapter', session: 'site:chatgpt', siteSession: 'persistent' });

    for (const call of daemonFetch.mock.calls) {
      const body = JSON.parse(String(call[1]?.body)) as { runId?: string; command?: string; access?: string };
      expect(body.runId).toBe('run_4242_1_a');
      expect(body.command).toBe('chatgpt ask');
      expect(body.access).toBe('write');
    }
  });

  it('clearDaemonRunContext only clears the context that still belongs to the runId', async () => {
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);
    setDaemonRunContext({ runId: 'run_4242_1_a', command: 'chatgpt ask', access: 'write' });

    // A stale run's deferred cleanup must not strip a different owner's context.
    clearDaemonRunContext('run_9999_2_b');
    await sendCommand('exec', { code: '1 + 1', surface: 'adapter', session: 'site:chatgpt', siteSession: 'persistent' });
    const kept = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { runId?: string };
    expect(kept.runId).toBe('run_4242_1_a');

    clearDaemonRunContext('run_4242_1_a');
    await sendCommand('exec', { code: '2 + 2', surface: 'adapter', session: 'site:chatgpt', siteSession: 'persistent' });
    const cleared = JSON.parse(String(daemonFetch.mock.calls[1][1]?.body)) as { runId?: string };
    expect(cleared.runId).toBeUndefined();
  });

  it('omits run-context fields when no run context is set (read/ephemeral commands)', async () => {
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await sendCommand('exec', { code: '1 + 1' });

    const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { runId?: string; access?: string };
    expect(body.runId).toBeUndefined();
    expect(body.access).toBeUndefined();
  });

  it('throws a terminal SessionBusyError on a session_busy response without retrying', async () => {
    daemonFetch.mockResolvedValue({
      status: 409,
      json: () => Promise.resolve({
        id: 'server',
        ok: false,
        errorCode: 'session_busy',
        error: 'Session "site:chatgpt" is busy: chatgpt ask (pid 111) has been driving it for 42s.',
        errorHint: 'Wait for it to finish, or stop it with `kill 111` if it is stuck. Read-only commands are not blocked.',
      }),
    } as Response);

    await expect(
      sendCommand('exec', { code: '1 + 1', surface: 'adapter', session: 'site:chatgpt', siteSession: 'persistent' }),
    ).rejects.toBeInstanceOf(SessionBusyError);
    // Terminal: no ensure-bridge / re-dispatch — exactly one request went out.
    expect(daemonFetch).toHaveBeenCalledTimes(1);
  });

  it.each(['slot_wait_timeout', 'slot_conflict'])('treats %s as a terminal SessionBusyError', async (errorCode) => {
    daemonFetch.mockResolvedValue({
      status: 503,
      json: () => Promise.resolve({ id: 'server', ok: false, errorCode, error: 'Slot admission rejected.' }),
    } as Response);

    await expect(sendCommand('slot-acquire', { site: 'xiaohongshu', runId: 'run_1_1_1', poolSize: 1 })).rejects.toBeInstanceOf(SessionBusyError);
    expect(daemonFetch).toHaveBeenCalledTimes(1);
  });

  it('sendCommand forwards OPENCLI_PROFILE as a hard contextId requirement', async () => {
    vi.stubEnv('OPENCLI_PROFILE', 'work');
    vi.spyOn(Date, 'now').mockReturnValue(1_763_000_000_000);
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await sendCommand('exec', { code: '1 + 1' });

    const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { contextId?: string; preferredContextId?: string };
    expect(body.contextId).toBe('work');
    expect(body.preferredContextId).toBeUndefined();
  });

  it('sendCommand forwards the config default as a soft preferredContextId, not a requirement', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opencli-dc-profile-'));
    fs.writeFileSync(
      path.join(configDir, 'browser-profiles.json'),
      JSON.stringify({ version: 1, aliases: {}, defaultContextId: 'zvypsyje' }),
    );
    vi.stubEnv('OPENCLI_CONFIG_DIR', configDir);
    vi.stubEnv('OPENCLI_PROFILE', '');
    try {
      daemonFetch.mockResolvedValue({
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
      } as Response);

      await sendCommand('exec', { code: '1 + 1' });

      const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { contextId?: string; preferredContextId?: string };
      expect(body.preferredContextId).toBe('zvypsyje');
      expect(body.contextId).toBeUndefined();
    } finally {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
  });

  it('sendCommand uses explicit windowMode before OPENCLI_WINDOW env fallback', async () => {
    vi.stubEnv('OPENCLI_WINDOW', 'foreground');
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await sendCommand('exec', { code: '1 + 1', windowMode: 'background' });

    const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { windowMode?: string };
    expect(body.windowMode).toBe('background');
  });

  it('sendCommand forwards OPENCLI_BROWSER_IDLE_TIMEOUT (seconds) as idleTimeout', async () => {
    vi.stubEnv('OPENCLI_BROWSER_IDLE_TIMEOUT', '300');
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await sendCommand('exec', { code: '1 + 1' });

    const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { idleTimeout?: number };
    expect(body.idleTimeout).toBe(300);
  });

  it('sendCommand uses explicit idleTimeout before OPENCLI_BROWSER_IDLE_TIMEOUT env fallback', async () => {
    vi.stubEnv('OPENCLI_BROWSER_IDLE_TIMEOUT', '300');
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await sendCommand('exec', { code: '1 + 1', idleTimeout: 45 });

    const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { idleTimeout?: number };
    expect(body.idleTimeout).toBe(45);
  });

  it.each(['0', '-5', '1.5', 'abc', ''])('sendCommand ignores invalid OPENCLI_BROWSER_IDLE_TIMEOUT=%j', async (raw) => {
    vi.stubEnv('OPENCLI_BROWSER_IDLE_TIMEOUT', raw);
    daemonFetch.mockResolvedValue({
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
    } as Response);

    await sendCommand('exec', { code: '1 + 1' });

    const body = JSON.parse(String(daemonFetch.mock.calls[0][1]?.body)) as { idleTimeout?: number };
    expect(body.idleTimeout).toBeUndefined();
  });

  it('sendCommand retries executor-transient errors ONCE with a NEW id (re-execution is a new logical attempt)', async () => {
    const fetchMock = daemonFetch;
    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: false, error: 'attach failed: interference', errorCode: 'attach_failed' }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 42 }),
      } as Response);

    await expect(sendCommand('exec', { code: '6 * 7' })).resolves.toBe(42);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const ids = fetchMock.mock.calls.map(([, init]) => {
      const body = JSON.parse(String(init?.body)) as { id: string };
      return body.id;
    });
    expect(ids[0]).not.toBe(ids[1]);
  });

  it('sendCommand does NOT retry mid-execution failures (detached_mid_command) — outcome is unknown', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: false, error: 'Detached while handling command', errorCode: 'detached_mid_command' }),
    } as Response);

    await expect(sendCommand('exec', { code: 'submit()' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'detached_mid_command',
    } satisfies Partial<BrowserCommandError>);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('sendCommand does not retry command_result_unknown even when the message looks transient', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValue({
      ok: false,
      status: 503,
      json: () => Promise.resolve({
        id: 'server',
        ok: false,
        errorCode: 'command_result_unknown',
        error: 'Extension disconnected after command timeout',
        errorHint: 'Inspect state before retrying.',
      }),
    } as Response);

    await expect(sendCommand('exec', { code: 'window.__mutate = true' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'command_result_unknown',
      hint: 'Inspect state before retrying.',
    } satisfies Partial<BrowserCommandError>);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  function mockEnsureReady(extensionVersion?: string, extensionCompatRange: string | null = '>=1.7.0') {
    return vi.spyOn(daemonLifecycle, 'ensureBrowserBridgeReady').mockResolvedValue({
      state: 'ready',
      status: {
        ok: true,
        pid: 1,
        uptime: 1,
        extensionConnected: true,
        ...(extensionVersion && { extensionVersion }),
        ...(extensionCompatRange && { extensionCompatRange }),
        pending: 0,
        memoryMB: 0,
        port: 19825,
      },
    });
  }

  it('sendCommand runs full bridge ensure on a pre-dispatch failure, then resends the SAME id', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_763_000_000_321);
    const ensureSpy = mockEnsureReady('1.0.22');
    const fetchMock = daemonFetch;
    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: () => Promise.resolve({
          ok: false,
          errorCode: 'extension_not_connected',
          error: 'Extension not connected.',
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 7 }),
      } as Response);

    await expect(sendCommand('exec', { code: '1 + 6', contextId: 'work', preferredContextId: 'zvypsyje' })).resolves.toBe(7);

    expect(ensureSpy).toHaveBeenCalledWith(expect.objectContaining({ contextId: 'work', preferredContextId: 'zvypsyje', verbose: false }));
    const ids = fetchMock.mock.calls.map(([, init]) => (JSON.parse(String(init?.body)) as { id: string }).id);
    expect(ids).toHaveLength(2);
    // Transport retries keep the id stable so the executor's journal can dedupe.
    expect(ids[0]).toBe(ids[1]);
  });

  it('sendCommand runs full bridge ensure on a pre-connect TypeError (ECONNREFUSED) before resending', async () => {
    const ensureSpy = mockEnsureReady();
    const refused = new TypeError('fetch failed');
    (refused as { cause?: unknown }).cause = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:19825'), { code: 'ECONNREFUSED' });
    const fetchMock = daemonFetch;
    fetchMock
      .mockRejectedValueOnce(refused)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 'ok' }),
      } as Response);

    await expect(sendCommand('exec', { code: 'document.title' })).resolves.toBe('ok');

    expect(ensureSpy).toHaveBeenCalledWith(expect.objectContaining({ verbose: false }));
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('sendCommand retries a post-connect drop with the SAME id when the extension journals ids', async () => {
    mockEnsureReady('1.0.22');
    const reset = new TypeError('fetch failed');
    (reset as { cause?: unknown }).cause = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
    const fetchMock = daemonFetch;
    fetchMock
      .mockRejectedValueOnce(reset)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 'replayed' }),
      } as Response);

    await expect(sendCommand('navigate', { url: 'https://example.com' })).resolves.toBe('replayed');

    const ids = fetchMock.mock.calls.map(([, init]) => (JSON.parse(String(init?.body)) as { id: string }).id);
    expect(ids).toHaveLength(2);
    expect(ids[0]).toBe(ids[1]);
  });

  it('sendCommand does NOT resend a post-connect drop when the extension predates the journal', async () => {
    const ensureSpy = mockEnsureReady('1.0.21');
    const reset = new TypeError('fetch failed');
    (reset as { cause?: unknown }).cause = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
    daemonFetch.mockRejectedValueOnce(reset);

    await expect(sendCommand('navigate', { url: 'https://example.com' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'command_result_unknown',
    } satisfies Partial<BrowserCommandError>);

    expect(ensureSpy).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('sendCommand does NOT resend a post-connect drop on the legacy extension version line', async () => {
    const ensureSpy = mockEnsureReady('1.7.2', null);
    const reset = new TypeError('fetch failed');
    (reset as { cause?: unknown }).cause = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
    daemonFetch
      .mockRejectedValueOnce(reset)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 'executed again' }),
      } as Response);

    await expect(sendCommand('navigate', { url: 'https://example.com' })).rejects.toMatchObject({
      code: 'command_result_unknown',
    });

    expect(ensureSpy).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('sendCommand retries daemon_shutting_down with the same id when the extension journals ids', async () => {
    mockEnsureReady('1.0.22');
    const fetchMock = daemonFetch;
    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: () => Promise.resolve({ ok: false, errorCode: 'daemon_shutting_down', error: 'Daemon shutting down before the command completed.' }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 'server', ok: true, data: 'replayed' }),
      } as Response);

    await expect(sendCommand('navigate', { url: 'https://example.com' })).resolves.toBe('replayed');

    const ids = fetchMock.mock.calls.map(([, init]) => (JSON.parse(String(init?.body)) as { id: string }).id);
    expect(ids).toHaveLength(2);
    expect(ids[0]).toBe(ids[1]);
  });

  it('sendCommand does NOT resend daemon_shutting_down on a legacy extension — outcome unknown', async () => {
    mockEnsureReady('1.0.21');
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: () => Promise.resolve({ ok: false, errorCode: 'daemon_shutting_down', error: 'Daemon shutting down before the command completed.' }),
    } as Response);

    await expect(sendCommand('navigate', { url: 'https://example.com' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'command_result_unknown',
    } satisfies Partial<BrowserCommandError>);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('sendCommand does NOT resend a bare TypeError on a legacy extension', async () => {
    const ensureSpy = mockEnsureReady('1.0.15');
    daemonFetch.mockRejectedValueOnce(new TypeError('fetch failed'));

    await expect(sendCommand('exec', { code: 'window.__mutate = true' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'command_result_unknown',
    } satisfies Partial<BrowserCommandError>);

    expect(ensureSpy).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('sendCommand does NOT wait when the bridge reports profile_required', async () => {
    const ensureSpy = vi.spyOn(daemonLifecycle, 'ensureBrowserBridgeReady');
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: () => Promise.resolve({
        ok: false,
        errorCode: 'profile_required',
        error: 'Multiple Browser Bridge profiles are connected; choose one with --profile.',
        errorHint: 'Run opencli profile list, then opencli profile use <name>.',
      }),
    } as Response);

    await expect(sendCommand('exec', { code: '1' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'profile_required',
    } satisfies Partial<BrowserCommandError>);

    expect(ensureSpy).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('sendCommand plumbs the default command timeout into body.timeout', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 1 }),
    } as Response);

    await expect(sendCommand('exec', { code: '1' })).resolves.toBe(1);

    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body)) as { timeout?: number };
    expect(body.timeout).toBe(120);
  });

  it('sendCommand extends body.timeout past an extension-side timeoutMs (wait-download)', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: { downloaded: true } }),
    } as Response);

    await sendCommand('wait-download', { timeoutMs: 240_000 });

    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body)) as { timeout?: number };
    // 240s extension wait + 15s margin
    expect(body.timeout).toBe(255);
  });

  it('setDaemonCommandTimeoutSeconds raises the transport deadline for the user --timeout', async () => {
    const fetchMock = daemonFetch;
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ id: 'server', ok: true, data: 1 }),
    } as Response);

    setDaemonCommandTimeoutSeconds(300);
    try {
      await sendCommand('exec', { code: '1' });
    } finally {
      setDaemonCommandTimeoutSeconds(null);
    }

    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body)) as { timeout?: number };
    expect(body.timeout).toBe(300);
  });

  it('client HTTP abort fires only after the daemon timer margin (timeout*1000 + 10s)', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = daemonFetch;
      let aborted = false;
      fetchMock.mockImplementationOnce((_url, init) => new Promise((_, reject) => {
        init?.signal?.addEventListener('abort', () => {
          aborted = true;
          reject(Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }));
        });
      }));

      const pending = sendCommand('exec', { code: '1' });
      const assertion = expect(pending).rejects.toMatchObject({
        name: 'BrowserCommandError',
        code: 'command_result_unknown',
      } satisfies Partial<BrowserCommandError>);

      // Just before the margin the daemon still owns the deadline — no abort.
      await vi.advanceTimersByTimeAsync(120_000 + 9_999);
      expect(aborted).toBe(false);

      await vi.advanceTimersByTimeAsync(1);
      expect(aborted).toBe(true);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it('sendCommand surfaces an AbortError as command_result_unknown without ensure or resend', async () => {
    const ensureSpy = vi.spyOn(daemonLifecycle, 'ensureBrowserBridgeReady');
    const abortErr = new Error('The operation was aborted');
    abortErr.name = 'AbortError';
    daemonFetch.mockRejectedValueOnce(abortErr);

    await expect(sendCommand('exec', { code: 'window.__mutate = true' })).rejects.toMatchObject({
      name: 'BrowserCommandError',
      code: 'command_result_unknown',
    } satisfies Partial<BrowserCommandError>);

    expect(ensureSpy).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('isUnknownOutcomeError', () => {
  it('is true for each unknown-outcome code', () => {
    for (const code of ['command_result_unknown', 'command_lost', 'result_evicted']) {
      expect(isUnknownOutcomeError(new BrowserCommandError('unknown', code))).toBe(true);
    }
  });

  it('is false for an ordinary failure code and for a success (no error)', () => {
    expect(isUnknownOutcomeError(new BrowserCommandError('boom', 'attach_failed'))).toBe(false);
    expect(isUnknownOutcomeError(new Error('plain failure'))).toBe(false);
    expect(isUnknownOutcomeError(undefined)).toBe(false);
    expect(isUnknownOutcomeError(null)).toBe(false);
  });

  it('unwraps an unknown-outcome error nested in a cause chain', () => {
    const wrapped = new Error('adapter failed', { cause: new BrowserCommandError('lost', 'command_lost') });
    expect(isUnknownOutcomeError(wrapped)).toBe(true);
  });
});
