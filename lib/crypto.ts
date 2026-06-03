/**
 * Zero-knowledge client-side encryption using the Web Crypto API.
 *
 * Design: the user's passphrase never leaves the browser. We derive a 256-bit
 * AES-GCM key from it with PBKDF2 (SHA-256, 210k iterations, per-file random
 * salt), then encrypt with a fresh random 96-bit IV. The server / S3 only ever
 * stores the ciphertext envelope — it cannot decrypt anything, because it never
 * sees the passphrase or the derived key.
 *
 * Envelope layout (single binary blob):
 *   [ magic "ZKV1" 4B ][ salt 16B ][ iv 12B ][ ciphertext + GCM tag ]
 *
 * Works in the browser and in Node 20+ (both expose globalThis.crypto.subtle),
 * which is what lets the crypto be unit-tested without a browser.
 */

const MAGIC = new Uint8Array([0x5a, 0x4b, 0x56, 0x31]); // "ZKV1"
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERATIONS = 210_000;

const subtle = globalThis.crypto.subtle;

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Encrypt raw bytes into a self-describing envelope (salt + iv + ciphertext). */
export async function encryptBytes(
  data: Uint8Array,
  passphrase: string
): Promise<Uint8Array> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv }, key, data)
  );
  return concat(MAGIC, salt, iv, ct);
}

/** Decrypt an envelope produced by encryptBytes. Throws on wrong passphrase
 * (GCM authentication failure) or a corrupt/foreign blob. */
export async function decryptBytes(
  envelope: Uint8Array,
  passphrase: string
): Promise<Uint8Array> {
  if (envelope.length < MAGIC.length + SALT_LEN + IV_LEN)
    throw new Error("blob too short to be a valid vault file");
  for (let i = 0; i < MAGIC.length; i++)
    if (envelope[i] !== MAGIC[i]) throw new Error("not a ZKV1 vault file");

  let off = MAGIC.length;
  const salt = envelope.slice(off, (off += SALT_LEN));
  const iv = envelope.slice(off, (off += IV_LEN));
  const ct = envelope.slice(off);
  const key = await deriveKey(passphrase, salt);
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  } catch {
    throw new Error("decryption failed — wrong passphrase or corrupted file");
  }
}

// ---- browser File helpers (no-ops in Node) -----------------------------

export async function encryptFile(file: File, passphrase: string): Promise<Blob> {
  const buf = new Uint8Array(await file.arrayBuffer());
  const env = await encryptBytes(buf, passphrase);
  return new Blob([env], { type: "application/octet-stream" });
}

export async function decryptFile(blob: Blob, passphrase: string): Promise<Uint8Array> {
  const buf = new Uint8Array(await blob.arrayBuffer());
  return decryptBytes(buf, passphrase);
}
