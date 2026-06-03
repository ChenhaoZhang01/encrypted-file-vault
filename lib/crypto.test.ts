import { test } from "node:test";
import assert from "node:assert/strict";
import { encryptBytes, decryptBytes } from "./crypto.ts";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

test("round-trips data with the correct passphrase", async () => {
  const plain = enc("the launch codes are 0000");
  const env = await encryptBytes(plain, "correct horse battery staple");
  const out = await decryptBytes(env, "correct horse battery staple");
  assert.equal(dec(out), "the launch codes are 0000");
});

test("ciphertext does not contain the plaintext", async () => {
  const env = await encryptBytes(enc("SECRET_TOKEN_123"), "pw");
  assert.ok(!dec(env).includes("SECRET_TOKEN_123"));
});

test("wrong passphrase fails authentication", async () => {
  const env = await encryptBytes(enc("hello"), "right-pass");
  await assert.rejects(() => decryptBytes(env, "wrong-pass"), /decryption failed/);
});

test("encryption is non-deterministic (random salt + iv)", async () => {
  const a = await encryptBytes(enc("same input"), "pw");
  const b = await encryptBytes(enc("same input"), "pw");
  assert.notDeepEqual(Array.from(a), Array.from(b));
});

test("rejects a non-vault blob", async () => {
  const garbage = new Uint8Array(40).fill(7); // long enough; wrong magic bytes
  await assert.rejects(() => decryptBytes(garbage, "pw"), /not a ZKV1/);
});

test("tampering with ciphertext is detected", async () => {
  const env = await encryptBytes(enc("integrity matters"), "pw");
  env[env.length - 1] ^= 0xff; // flip a bit in the GCM tag region
  await assert.rejects(() => decryptBytes(env, "pw"));
});
