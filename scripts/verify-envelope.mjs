#!/usr/bin/env node
/**
 * verify-envelope.mjs — pre-publish guard for the encrypted pricing hub.
 *
 * Validates that index.html still contains a well-formed, strongly-derived
 * encrypted payload so a corrupted or accidentally-weakened build can never
 * reach GitHub Pages.
 *
 * Structural checks (always run, no secret needed):
 *   - the `const ENC={...}` envelope exists and exposes salt / iv / ct / iter
 *   - salt, iv and ct are valid base64; iv decodes to a 12-byte AES-GCM nonce
 *   - iter (PBKDF2 iteration count) is at least ITER_FLOOR
 *   - the unlock path still uses PBKDF2 + AES-GCM (no silent crypto downgrade)
 *   - the file is at least MIN_BYTES (guards against the payload being
 *     replaced by something tiny — e.g. an unencrypted stub)
 *
 * End-to-end check (only when MONTY_TEST_PW is set in the environment):
 *   - actually derives the key and decrypts ct, asserting the result looks
 *     like HTML. This is the strongest guard; wire the password in as a repo
 *     secret named MONTY_TEST_PW to enable it in CI.
 *
 * Exit code 0 = pass, 1 = fail. No third-party dependencies.
 */
import { readFile } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';

const FILE = process.argv[2] || 'index.html';
const ITER_FLOOR = 600000;      // modern PBKDF2/SHA-256 minimum
const MIN_BYTES = 500_000;      // encrypted dataset is ~2.8MB; anything tiny is suspect

const fail = [];
const ok = [];
const b64re = /^[A-Za-z0-9+/]+={0,2}$/;

function b64bytes(s) {
  return Buffer.from(s, 'base64');
}

const html = await readFile(FILE, 'utf8');

// --- size gate -------------------------------------------------------------
if (html.length < MIN_BYTES) {
  fail.push(`file is only ${html.length} bytes (< ${MIN_BYTES}); payload may be missing`);
} else {
  ok.push(`file size ${html.length} bytes`);
}

// --- extract the envelope fields (keys are unquoted in the minified head) ---
const salt = html.match(/\bsalt:"([^"]+)"/)?.[1];
const iv   = html.match(/\biv:"([^"]+)"/)?.[1];
const ct   = html.match(/\bct:"([^"]+)"/)?.[1];
const iter = Number(html.match(/\biter:(\d+)/)?.[1]);

if (!salt || !iv || !ct || !Number.isFinite(iter)) {
  fail.push(`could not find a complete ENC envelope (salt=${!!salt} iv=${!!iv} ct=${!!ct} iter=${iter})`);
} else {
  ok.push('ENC envelope present');

  for (const [name, val] of [['salt', salt], ['iv', iv], ['ct', ct]]) {
    if (!b64re.test(val)) fail.push(`${name} is not valid base64`);
  }

  const ivLen = b64bytes(iv).length;
  if (ivLen !== 12) fail.push(`iv is ${ivLen} bytes; AES-GCM expects a 12-byte nonce`);
  else ok.push('iv is a 12-byte nonce');

  const ctLen = b64bytes(ct).length;
  if (ctLen < 1000) fail.push(`ciphertext is only ${ctLen} bytes`);
  else ok.push(`ciphertext ${ctLen} bytes`);

  if (!(iter >= ITER_FLOOR)) fail.push(`iter=${iter} is below the ${ITER_FLOOR} floor`);
  else ok.push(`iter=${iter} (>= ${ITER_FLOOR})`);
}

// --- crypto-downgrade guard ------------------------------------------------
if (!/PBKDF2/.test(html)) fail.push('PBKDF2 no longer referenced in the unlock path');
if (!/AES-GCM/.test(html)) fail.push('AES-GCM no longer referenced in the unlock path');
if (/PBKDF2/.test(html) && /AES-GCM/.test(html)) ok.push('unlock path still uses PBKDF2 + AES-GCM');

// --- optional end-to-end decrypt ------------------------------------------
const testPw = process.env.MONTY_TEST_PW;
if (testPw && salt && iv && ct && Number.isFinite(iter)) {
  try {
    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(testPw), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64bytes(salt), iterations: iter, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64bytes(iv) }, key, b64bytes(ct));
    const text = new TextDecoder().decode(pt);
    if (/<html|<!doctype|<body|const ENC=/i.test(text)) ok.push('end-to-end decrypt succeeded (payload looks like HTML)');
    else fail.push('decrypt succeeded but result does not look like HTML');
  } catch (e) {
    fail.push(`end-to-end decrypt failed with MONTY_TEST_PW (wrong password or corrupt ciphertext): ${e.message}`);
  }
} else if (!testPw) {
  ok.push('end-to-end decrypt skipped (set MONTY_TEST_PW to enable)');
}

// --- report ----------------------------------------------------------------
for (const m of ok) console.log(`  ok   ${m}`);
for (const m of fail) console.error(`  FAIL ${m}`);
console.log(`\n${fail.length ? '✗' : '✓'} ${FILE}: ${ok.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
