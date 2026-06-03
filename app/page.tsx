"use client";

import { useState } from "react";
import { encryptFile, decryptFile } from "@/lib/crypto";

function download(data: BlobPart, filename: string) {
  const url = URL.createObjectURL(new Blob([data]));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [pass, setPass] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function doEncrypt() {
    if (!file || !pass) return setStatus("Pick a file and enter a passphrase.");
    setBusy(true);
    try {
      const blob = await encryptFile(file, pass);
      download(blob, file.name + ".zkv");
      setStatus(`Encrypted ${file.name} → ${file.name}.zkv (${blob.size} bytes). The passphrase never left your browser.`);
    } catch (e) {
      setStatus("Encryption error: " + (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function doDecrypt() {
    if (!file || !pass) return setStatus("Pick a .zkv file and enter the passphrase.");
    setBusy(true);
    try {
      const bytes = await decryptFile(file, pass);
      const outName = file.name.replace(/\.zkv$/, "") || "decrypted.bin";
      download(bytes, outName);
      setStatus(`Decrypted → ${outName} (${bytes.length} bytes).`);
    } catch (e) {
      setStatus((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 620, margin: "0 auto", padding: "40px 20px" }}>
      <h1>🔐 Encrypted File Vault</h1>
      <p style={{ color: "#8b949e" }}>
        Client-side AES-256-GCM with a PBKDF2-derived key. Zero-knowledge: your
        passphrase and plaintext never touch the network.
      </p>

      <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: 12, padding: 20, display: "grid", gap: 14 }}>
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          style={{ color: "#e6edf3" }}
        />
        <input
          type="password"
          placeholder="Passphrase"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          style={{ background: "#0d1117", color: "#e6edf3", border: "1px solid #30363d", borderRadius: 8, padding: 10 }}
        />
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={doEncrypt} disabled={busy} style={btn("#1f6feb")}>Encrypt & download</button>
          <button onClick={doDecrypt} disabled={busy} style={btn("#238636")}>Decrypt & download</button>
        </div>
      </div>

      {status && (
        <p style={{ marginTop: 16, padding: 12, background: "#161b22", border: "1px solid #30363d", borderRadius: 8, fontSize: 14 }}>
          {status}
        </p>
      )}

      <details style={{ marginTop: 24, color: "#8b949e" }}>
        <summary>How zero-knowledge works here</summary>
        <p>
          A random 16-byte salt + PBKDF2 (210k iterations, SHA-256) turn your
          passphrase into a 256-bit AES-GCM key, used with a fresh random IV.
          Only the envelope <code>[magic | salt | iv | ciphertext+tag]</code> is
          ever stored or uploaded. The server can hold the blob but can never
          read it — it has no key and never sees your passphrase.
        </p>
      </details>
    </main>
  );
}

const btn = (bg: string) => ({
  background: bg, color: "#fff", border: 0, borderRadius: 8,
  padding: "10px 16px", cursor: "pointer", flex: 1,
});
