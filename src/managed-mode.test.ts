/**
 * OPENCLI_DAEMON_MANAGED=1 runs built-in code only: user adapters and plugins
 * planted in ~/.opencli are never loaded, nothing is written under HOME, and
 * no update check runs. A control run without the flag proves the planted
 * fixtures would otherwise load and the update check would otherwise fire.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function plantHome(): { home: string; markers: string } {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'opencli-managed-home-'));
  const markers = fs.mkdtempSync(path.join(os.tmpdir(), 'opencli-managed-markers-'));
  const evil = (marker: string, site: string, name: string, description: string) => [
    "import { writeFileSync } from 'node:fs';",
    "import { cli, Strategy } from '@jackwener/opencli/registry';",
    `writeFileSync(${JSON.stringify(path.join(markers, marker))}, 'loaded');`,
    `cli({ site: '${site}', name: '${name}', access: 'read', description: '${description}', strategy: Strategy.PUBLIC, browser: false, args: [], func: async () => [] });`,
    '',
  ].join('\n');
  // Same site/name as a built-in command: would override it if loaded.
  fs.mkdirSync(path.join(home, '.opencli', 'clis', 'hackernews'), { recursive: true });
  fs.writeFileSync(path.join(home, '.opencli', 'clis', 'hackernews', 'top.js'), evil('user-adapter', 'hackernews', 'top', 'EVIL user override'));
  fs.mkdirSync(path.join(home, '.opencli', 'plugins', 'evil'), { recursive: true });
  fs.writeFileSync(path.join(home, '.opencli', 'plugins', 'evil', 'evil.js'), evil('plugin', 'evil', 'pwn', 'EVIL plugin'));
  return { home, markers };
}

function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      out.push(path.relative(dir, p) + (e.isSymbolicLink() ? ' -> link' : ''));
      if (e.isDirectory() && !e.isSymbolicLink()) walk(p);
    }
  };
  walk(dir);
  return out.sort();
}

let proxy: Server;
let proxyHits: string[] = [];
let proxyUrl: string;

beforeAll(async () => {
  // Records any outbound HTTP(S) attempt (update checks go through the proxy).
  proxy = createServer((req, res) => { proxyHits.push(`${req.method} ${req.url}`); res.writeHead(502); res.end(); });
  proxy.on('connect', (req, socket) => { proxyHits.push(`CONNECT ${req.url}`); socket.destroy(); });
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
});
afterAll(async () => { await new Promise((resolve) => proxy.close(resolve)); });

function runCli(home: string, args: string[], managed: boolean) {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, NO_PROXY: '' };
  delete env.CI;
  delete env.CONTINUOUS_INTEGRATION;
  delete env.OPENCLI_CONFIG_DIR;
  delete env.OPENCLI_CACHE_DIR;
  env.OPENCLI_DAEMON_TOKEN_FILE = path.join(os.tmpdir(), 'opencli-managed-no-token');
  if (managed) env.OPENCLI_DAEMON_MANAGED = '1';
  else delete env.OPENCLI_DAEMON_MANAGED;
  return spawnSync(process.execPath, ['--import', 'tsx/esm', path.join(ROOT, 'src', 'main.ts'), ...args], {
    cwd: ROOT, env, encoding: 'utf-8', timeout: 60_000,
  });
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('OPENCLI_DAEMON_MANAGED=1 runs built-in code only', () => {
  it('ignores planted user adapters/plugins, writes nothing under HOME, and makes no update check', async () => {
    const { home, markers } = plantHome();
    const before = snapshot(home);
    proxyHits = [];

    const res = runCli(home, ['hackernews', 'top', '--help'], true);
    await sleep(500); // let any stray background request reach the proxy

    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toContain('Hacker News top stories');
    expect(res.stdout + res.stderr).not.toContain('EVIL');
    expect(fs.readdirSync(markers)).toEqual([]);
    expect(snapshot(home)).toEqual(before);
    expect(proxyHits).toEqual([]);

    const blocked = runCli(home, ['plugin', 'list'], true);
    expect(blocked.status).toBe(78);
    expect(blocked.stdout + blocked.stderr).toContain('OPENCLI_DAEMON_MANAGED=1');
    expect(snapshot(home)).toEqual(before);
    expect(fs.readdirSync(markers)).toEqual([]);
  }, 120_000);

  it('control: without the flag the same fixtures load, HOME is written and the update check fires', async () => {
    const { home, markers } = plantHome();
    const before = snapshot(home);
    proxyHits = [];

    const res = runCli(home, ['hackernews', 'top', '--help'], false);
    await sleep(1_500);

    expect(res.stdout).toContain('EVIL user override');
    expect(fs.readdirSync(markers).sort()).toEqual(['plugin', 'user-adapter']);
    expect(snapshot(home)).not.toEqual(before);
    expect(fs.existsSync(path.join(home, '.opencli', 'update-check.json'))).toBe(true);
    expect(proxyHits.length).toBeGreaterThan(0);
  }, 120_000);
});
