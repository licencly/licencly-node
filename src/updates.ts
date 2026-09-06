import { createHash, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

import { ApiError, NetworkError } from "./errors.js";

/** Mirrors the server's vocabulary exactly, so a vendor's logs match the API. */
export const UpdateOutcome = {
  Available: "update_available",
  UpToDate: "up_to_date",
  /**
   * NOT an error. A newer release exists and this license is not entitled to
   * it; `latest` names what a renewal would unlock.
   */
  MaintenanceLapsed: "maintenance_lapsed",
  /** An entitled release exists but needs an intermediate version first. */
  UpgradeBlocked: "upgrade_blocked",
  NotEntitled: "not_entitled",
} as const;

export type UpdateOutcomeValue = (typeof UpdateOutcome)[keyof typeof UpdateOutcome];

export interface Release {
  uuid: string;
  version: string;
  channel: string;
  platform: string;
  arch: string;
  notes: string;
  min_upgrade_from: string;
  artifact_size: number;
  artifact_sha256: string;
  artifact_filename: string;
  signed: boolean;
}

export interface UpdateResult {
  outcome: UpdateOutcomeValue;
  /** The release to install, when outcome is Available. */
  release?: Release;
  /** What a renewal would unlock, when held back. */
  latest?: Release;
  downloadUrl?: string;
}

export interface UpdateQuery {
  currentVersion?: string;
  channel?: string;
  platform?: string;
  arch?: string;
}

/** The single check for "should I offer an update". */
export function updateAvailable(result: UpdateResult): boolean {
  return result.outcome === UpdateOutcome.Available;
}

/**
 * A newer release exists but this license cannot have it: a prompt, not a
 * failure.
 */
export function renewalWouldUnlock(result: UpdateResult): boolean {
  return result.outcome === UpdateOutcome.MaintenanceLapsed && result.latest !== undefined;
}

export async function checkForUpdate(
  request: (path: string) => Promise<unknown>,
  productUuid: string,
  licenseKey: string,
  query: UpdateQuery,
): Promise<UpdateResult> {
  const params = new URLSearchParams({ key: licenseKey });
  if (query.currentVersion) params.set("version", query.currentVersion);
  if (query.channel) params.set("channel", query.channel);
  if (query.platform) params.set("platform", query.platform);
  if (query.arch) params.set("arch", query.arch);

  const raw = (await request(
    `/v1/products/${encodeURIComponent(productUuid)}/updates/check?${params}`,
  )) as {
    outcome: UpdateOutcomeValue;
    release?: Release;
    latest?: Release;
    download_url?: string;
  };

  return {
    outcome: raw.outcome,
    release: raw.release,
    latest: raw.latest,
    downloadUrl: raw.download_url,
  };
}

export class ArtifactError extends Error {
  constructor(
    message: string,
    readonly reason: "checksum" | "signature" | "unsigned",
  ) {
    super(`licencly: ${message}`);
    this.name = "ArtifactError";
  }
}

/** 30 minutes. See the note on the fetch call below. */
export const DEFAULT_DOWNLOAD_TIMEOUT_MS = 30 * 60 * 1000;

export interface DownloadOptions {
  baseUrl: string;
  productUuid: string;
  licenseKey: string;
  release: Release;
  destDir: string;
  /**
   * YOUR Ed25519 public key, compiled into this application, not fetched from
   * Licencly. Licencly stores and serves the signature but cannot produce one,
   * so a compromise of Licencly cannot push code to your users.
   *
   * Omitting it reduces the check to corruption detection.
   */
  artifactKey?: KeyObject;
  userAgent: string;
  /** Bounds the download. Defaults to DEFAULT_DOWNLOAD_TIMEOUT_MS. */
  timeoutMs?: number;
}

/** Downloads a release and verifies it before returning a path. */
export async function downloadArtifact(options: DownloadOptions): Promise<string> {
  const { baseUrl, productUuid, licenseKey, release, destDir } = options;

  const url =
    `${baseUrl}/v1/products/${encodeURIComponent(productUuid)}` +
    `/releases/${encodeURIComponent(release.uuid)}/download?key=${encodeURIComponent(licenseKey)}`;

  let response: Response;
  try {
    response = await globalThis.fetch(url, {
      headers: { "User-Agent": options.userAgent },
      // Generous on purpose. An artifact is an installer, often hundreds of
      // megabytes, so the API timeout would abort most downloads; unbounded
      // would hang forever on a stalled connection.
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS),
    });
  } catch (err) {
    throw new NetworkError(err);
  }

  if (!response.ok) {
    throw new ApiError(response.status, "download_failed", `download failed (${response.status})`);
  }

  await mkdir(destDir, { recursive: true, mode: 0o750 });

  const name = basename(release.artifact_filename || "artifact.bin");
  // Download to a temporary name and rename only after verification, so a
  // half-written or unverified artifact is never left where something might
  // execute it.
  const tmp = join(destDir, `.${name}.partial`);
  const final = join(destDir, name);

  try {
    const bytes = Buffer.from(await response.arrayBuffer());
    await writeFile(tmp, bytes, { mode: 0o640 });

    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== release.artifact_sha256) {
      throw new ArtifactError(
        `downloaded artifact does not match its checksum: got ${digest}, expected ${release.artifact_sha256}`,
        "checksum",
      );
    }

    if (options.artifactKey) {
      const encoded = response.headers.get("X-Artifact-Signature");
      if (!encoded) {
        throw new ArtifactError("artifact carries no signature", "unsigned");
      }

      // Re-read from disk rather than trusting the buffer, so what is verified
      // is exactly what will be executed.
      const written = await readFile(tmp);
      if (!cryptoVerify(null, written, options.artifactKey, Buffer.from(encoded, "base64"))) {
        throw new ArtifactError(
          "artifact signature does not verify against your artifact key",
          "signature",
        );
      }
    }

    await rename(tmp, final);
    return final;
  } catch (err) {
    await rm(tmp, { force: true });
    throw err;
  }
}
