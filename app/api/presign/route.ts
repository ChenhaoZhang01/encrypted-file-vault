import { NextRequest, NextResponse } from "next/server";

/**
 * Issues a short-lived S3 presigned PUT URL so the *already-encrypted* blob can
 * be uploaded directly from the browser to S3 — the server never touches file
 * bytes (and they're ciphertext anyway). Requires AWS creds + S3_BUCKET; absent
 * those, the app still works as a pure local encrypt/decrypt tool.
 */
export async function POST(req: NextRequest) {
  const { key, contentType } = (await req.json()) as { key: string; contentType?: string };
  if (!process.env.S3_BUCKET || !process.env.AWS_ACCESS_KEY_ID) {
    return NextResponse.json({ error: "S3 not configured" }, { status: 503 });
  }
  try {
    // Lazy import so the dep is optional.
    const { S3Client, PutObjectCommand } = await import("@aws-sdk/client-s3");
    const { getSignedUrl } = await import("@aws-sdk/s3-request-presigner");
    const s3 = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });
    const safeKey = `vault/${key.replace(/[^a-zA-Z0-9._-]/g, "_")}`;
    const url = await getSignedUrl(
      s3,
      new PutObjectCommand({
        Bucket: process.env.S3_BUCKET,
        Key: safeKey,
        ContentType: contentType || "application/octet-stream",
      }),
      { expiresIn: 300 }
    );
    return NextResponse.json({ url, key: safeKey });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
