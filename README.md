# Encrypted File Vault

Zero-knowledge file encryption in the browser. Files are encrypted with
**AES-256-GCM** using a key derived from your passphrase via **PBKDF2** — the
passphrase and plaintext **never leave the client**. The server (and S3) only
ever hold ciphertext they can't read.

![stack](https://img.shields.io/badge/stack-Next.js%20·%20Web%20Crypto%20·%20S3-1f6feb)

## Zero-knowledge, concretely

1. A random **16-byte salt** + **PBKDF2** (SHA-256, 210,000 iterations) turn
   your passphrase into a 256-bit AES-GCM key.
2. Encryption uses a fresh random **96-bit IV** every time.
3. The output is a self-describing envelope:

   ```
   [ magic "ZKV1" 4B ][ salt 16B ][ iv 12B ][ ciphertext + GCM tag ]
   ```

4. Only that envelope is stored or uploaded. The server has **no key** and
   never sees the passphrase, so it cannot decrypt anything. GCM's auth tag
   also means any tampering is detected on decrypt.

All crypto is in [`lib/crypto.ts`](lib/crypto.ts) using the standard Web Crypto
API (`crypto.subtle`), which runs in the browser **and** in Node — which is how
it's unit-tested headlessly.

## Run it

```bash
npm install
npm run dev          # http://localhost:3000
```

Pick a file, enter a passphrase, **Encrypt & download** the `.zkv`. To recover,
load the `.zkv`, enter the same passphrase, **Decrypt & download**.

### Optional: store blobs in S3

Set AWS creds + `S3_BUCKET` (see `.env.example`). `POST /api/presign` returns a
short-lived presigned PUT URL so the browser uploads the **already-encrypted**
blob straight to S3 — the server never handles file bytes.

## Tests

```bash
npm test
```

Verifies passphrase round-trip, that ciphertext never contains the plaintext,
that a wrong passphrase fails GCM authentication, that encryption is
non-deterministic (random salt/IV), foreign-blob rejection, and tamper
detection.

## Security notes

- PBKDF2 at 210k iterations follows current OWASP guidance for SHA-256.
- AES-GCM provides confidentiality **and** integrity (authenticated encryption).
- There is no passphrase recovery by design — lose it and the data is gone.
