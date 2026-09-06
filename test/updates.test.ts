import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { LicenclyClient, MemoryCache } from "../src/index.js";

// The artifact path backs the claim that a compromise of Licencly cannot push
// code to a vendor's users. Each of these checks a way that could be lost.

function sha256Hex(body: Buffer): string {
  return createHash("sha256").update(body).digest("hex");
}

async function withServer(
  body: Buffer,
  signature: string | undefined,
  run: (client: LicenclyClient, dir: string) => Promise<void>,
): Promise<void> {
  const server: Server = createServer((_req, res) => {
    if (signature) res.setHeader("X-Artifact-Signature", signature);
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;

  const { publicKey } = generateKeyPairSync("ed25519");
  const client = new LicenclyClient({
    productUuid: "product-uuid",
    publicKeys: new Map([["k", publicKey]]),
    cache: new MemoryCache(),
    baseUrl: `http://127.0.0.1:${port}`,
    retries: 0,
  });

  const dir = mkdtempSync(join(tmpdir(), "licencly-test-"));
  try {
    await run(client, dir);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("a verified artifact is written to disk", async () => {
  const body = Buffer.from("this is a release artifact");
  await withServer(body, undefined, async (client, dir) => {
    const path = await client.downloadArtifact("KEY", {
      uuid: "rel-1",
      version: "4.0.0",
      channel: "stable",
      platform: "",
      arch: "",
      notes: "",
      min_upgrade_from: "",
      artifact_size: body.length,
      artifact_sha256: sha256Hex(body),
      artifact_filename: "acme-cad-4.0.0.bin",
      signed: false,
    }, dir);

    assert.equal(readFileSync(path).toString(), body.toString());
  });
});

test("a checksum mismatch is refused and leaves nothing behind", async () => {
  const body = Buffer.from("tampered bytes");
  await withServer(body, undefined, async (client, dir) => {
    await assert.rejects(
      () => client.downloadArtifact("KEY", {
        uuid: "rel-1", version: "4.0.0", channel: "stable", platform: "", arch: "",
        notes: "", min_upgrade_from: "", artifact_size: body.length,
        artifact_sha256: sha256Hex(Buffer.from("the bytes we expected")),
        artifact_filename: "app.bin", signed: false,
      }, dir),
      /checksum/,
    );
    assert.deepEqual(readdirSync(dir), [], "a refused artifact was left on disk");
  });
});

// The case the design exists for: bytes that pass the checksum but were not
// signed by the vendor.
test("a foreign signature is refused and leaves nothing behind", async () => {
  const body = Buffer.from("substituted release");
  const attacker = generateKeyPairSync("ed25519");
  const vendor = generateKeyPairSync("ed25519");
  const signature = edSign(null, body, attacker.privateKey).toString("base64");

  await withServer(body, signature, async (client, dir) => {
    await assert.rejects(
      () => client.downloadArtifact("KEY", {
        uuid: "rel-1", version: "4.0.0", channel: "stable", platform: "", arch: "",
        notes: "", min_upgrade_from: "", artifact_size: body.length,
        artifact_sha256: sha256Hex(body), artifact_filename: "app.bin", signed: true,
      }, dir, vendor.publicKey),
      /signature/,
    );
    assert.deepEqual(readdirSync(dir), [], "a refused artifact was left on disk");
  });
});

// Asking for signature verification and getting no signature is a refusal, not
// a silent downgrade to a checksum.
test("an unsigned artifact is refused when a key was supplied", async () => {
  const body = Buffer.from("unsigned release");
  const vendor = generateKeyPairSync("ed25519");

  await withServer(body, undefined, async (client, dir) => {
    await assert.rejects(
      () => client.downloadArtifact("KEY", {
        uuid: "rel-1", version: "4.0.0", channel: "stable", platform: "", arch: "",
        notes: "", min_upgrade_from: "", artifact_size: body.length,
        artifact_sha256: sha256Hex(body), artifact_filename: "app.bin", signed: false,
      }, dir, vendor.publicKey),
      /signature/,
    );
    assert.deepEqual(readdirSync(dir), [], "a refused artifact was left on disk");
  });
});

// The filename comes from the server and must not be able to place a file
// outside the directory the caller named.
test("a filename cannot escape the destination", async () => {
  const body = Buffer.from("release");
  for (const name of ["../escaped.bin", "../../escaped.bin", "/etc/escaped.bin", ""]) {
    await withServer(body, undefined, async (client, dir) => {
      const dest = join(dir, "downloads");
      const path = await client.downloadArtifact("KEY", {
        uuid: "rel-1", version: "4.0.0", channel: "stable", platform: "", arch: "",
        notes: "", min_upgrade_from: "", artifact_size: body.length,
        artifact_sha256: sha256Hex(body), artifact_filename: name, signed: false,
      }, dest);

      assert.ok(
        path.startsWith(dest + "/"),
        `filename ${JSON.stringify(name)} wrote to ${path}, outside ${dest}`,
      );
    });
  }
});
