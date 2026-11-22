/**
 * Extension side of the daemon HMAC protocol (mirror of src/daemon-auth.ts).
 * The token never leaves the extension: requests carry
 * HMAC-SHA256(key, [METHOD, path+query, ts, nonce, sha256hex(body)].join("\n")),
 * and the daemon proves itself with HMAC(key, "opencli-daemon-proof\n" + nonce).
 */

const enc = new TextEncoder();

function toHex(bytes: ArrayBuffer | Uint8Array): string {
  return [...(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

export function importDaemonKey(token: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(token), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function hmacHex(key: CryptoKey, data: string): Promise<string> {
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

export interface SignatureParts { ts: string; nonce: string; sig: string }

export async function signParts(key: CryptoKey, method: string, pathAndQuery: string, body = ''): Promise<SignatureParts> {
  const ts = String(Date.now());
  const nonce = randomNonce();
  const bodyHash = toHex(await crypto.subtle.digest('SHA-256', enc.encode(body)));
  const sig = await hmacHex(key, [method.toUpperCase(), pathAndQuery, ts, nonce, bodyHash].join('\n'));
  return { ts, nonce, sig };
}

export function authorizationHeader(parts: SignatureParts): string {
  return `OpenCLI-HMAC ts=${parts.ts};nonce=${parts.nonce};sig=${parts.sig}`;
}

export function expectedDaemonProof(key: CryptoKey, nonce: string): Promise<string> {
  return hmacHex(key, `opencli-daemon-proof\n${nonce}`);
}

/** Length check, then constant-time compare. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Daemon response authentication: X-OpenCLI-Proof =
 * HMAC(key, "opencli-response\n" + challenge + "\n" + status + "\n" + sha256hex(body)).
 */
export async function verifyResponseProof(
  key: CryptoKey, challenge: string, status: number, body: ArrayBuffer, proof: string | null,
): Promise<boolean> {
  if (!proof) return false;
  const bodyHash = toHex(await crypto.subtle.digest('SHA-256', body));
  return constantTimeEqual(proof, await hmacHex(key, `opencli-response\n${challenge}\n${status}\n${bodyHash}`));
}
