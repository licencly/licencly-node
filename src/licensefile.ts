import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

/**
 * The signed license file format.
 *
 * This is a standalone copy of the format logic, not an import from a shared
 * package: pulling in a licensing SDK should give you one dependency, not a
 * tree. Every Licencly SDK carries its own, and the conformance vectors in
 * `testdata/vectors.json` are what keep them in agreement.
 *
 * Format: `lcl1.<base64url(payload)>.<base64url(signature)>`
 *
 * The signature covers the ASCII of `lcl1.<payload>`: the bytes exactly as
 * transmitted. That removes any need for canonical JSON: two parsers that
 * disagree about key ordering would otherwise compute different digests and
 * reject each other's valid files.
 */

/** Format version, part of the signed bytes so a future format cannot be relabelled as this one. */
export const PREFIX = "lcl1";

/** License file schema version, distinct from the SDK's own version. */
export const FORMAT_VERSION = 1;

export const Status = {
  Active: "active",
  Suspended: "suspended",
  Revoked: "revoked",
  Expired: "expired",
} as const;

export type LicenseStatus = (typeof Status)[keyof typeof Status];

/** Verified content of a license file. */
/**
 * The verified content of a license file.
 *
 * The names here are the ones the Go and .NET SDKs use, not the short keys the
 * wire format uses. `maintenanceExpiresAt` says what it is; `mnt` needs the
 * format spec open beside it, and a vendor moving between two of our SDKs
 * should not have to relearn the same object.
 *
 * Readonly because these have been verified. Go returns Claims by value and the
 * .NET and Python types are immutable; this is the same property in TypeScript.
 */
export interface Claims {
  readonly version: number;
  readonly keyId: string;
  readonly licenseUuid: string;
  readonly key: string;
  readonly productUuid: string;
  readonly customerRef: string;
  readonly status: LicenseStatus;
  readonly seats: number;
  readonly used: number;
  readonly fingerprint: string;
  /** Seconds since the epoch. */
  readonly issuedAt: number;
  /** Seconds since the epoch; 0 for a perpetual license. */
  readonly expiresAt: number;
  /** Seconds since the epoch; 0 when maintenance never lapses. */
  readonly maintenanceExpiresAt: number;
  /** Seconds since the epoch: when the client should check in again. */
  readonly revalidateAfter: number;
  readonly graceSeconds: number;
  readonly metadata?: Record<string, unknown>;
}

/** The file as it arrives, before the short keys are given readable names. */
interface WireClaims {
  v: number;
  kid: string;
  lic: string;
  key: string;
  prd: string;
  sub: string;
  st: LicenseStatus;
  seats: number;
  used: number;
  fp: string;
  iat: number;
  exp: number;
  mnt: number;
  rev: number;
  grace: number;
  meta?: Record<string, unknown>;
}

function fromWire(w: WireClaims): Claims {
  return {
    version: w.v,
    keyId: w.kid,
    licenseUuid: w.lic,
    key: w.key,
    productUuid: w.prd,
    customerRef: w.sub,
    status: w.st,
    seats: w.seats,
    used: w.used,
    fingerprint: w.fp,
    issuedAt: w.iat,
    expiresAt: w.exp,
    maintenanceExpiresAt: w.mnt,
    revalidateAfter: w.rev,
    graceSeconds: w.grace,
    metadata: w.meta,
  };
}

export class LicenseFileError extends Error {
  constructor(
    message: string,
    readonly reason: "malformed" | "unknown_version" | "bad_signature" | "unknown_key",
  ) {
    super(message);
    this.name = "LicenseFileError";
  }
}

/**
 * Wraps a raw 32-byte Ed25519 public key so node:crypto will accept it.
 *
 * Node wants SPKI DER, and the prefix for Ed25519 is fixed, so this is a
 * constant header plus the key.
 */
export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) {
    throw new LicenseFileError(
      `public key is ${raw.length} bytes, want 32`,
      "unknown_key",
    );
  }
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([spkiPrefix, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

/** Parses a base64 public key, as copied from the dashboard. */
export function publicKeyFromBase64(encoded: string): KeyObject {
  return publicKeyFromRaw(Buffer.from(encoded, "base64"));
}

interface Split {
  signed: Buffer;
  claims: Claims;
  signature: Buffer;
}

function split(token: string): Split {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new LicenseFileError("license file is malformed", "malformed");
  }
  const [prefix, payload, signature] = parts as [string, string, string];

  if (prefix !== PREFIX) {
    throw new LicenseFileError(`unsupported license file version "${prefix}"`, "unknown_version");
  }

  let wire: WireClaims;
  try {
    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    wire = JSON.parse(decoded) as WireClaims;
  } catch {
    throw new LicenseFileError("license file is malformed", "malformed");
  }
  if (typeof wire !== "object" || wire === null) {
    throw new LicenseFileError("license file is malformed", "malformed");
  }
  if (wire.v !== FORMAT_VERSION) {
    throw new LicenseFileError(`unsupported license file version ${wire.v}`, "unknown_version");
  }

  return {
    signed: Buffer.from(`${prefix}.${payload}`, "ascii"),
    claims: fromWire(wire),
    signature: Buffer.from(signature, "base64url"),
  };
}

/**
 * Parses the payload WITHOUT verifying the signature.
 *
 * Its only legitimate use is reading `kid` to choose a public key. Every claim
 * is attacker-controlled until `verify` has succeeded.
 */
export function decode(token: string): Claims {
  return split(token).claims;
}

/** Checks the signature. Does not evaluate expiry, status or machine binding. */
export function verify(token: string, publicKey: KeyObject): Claims {
  const { signed, claims, signature } = split(token);

  if (!cryptoVerify(null, signed, publicKey, signature)) {
    throw new LicenseFileError("signature does not verify", "bad_signature");
  }
  return claims;
}

/**
 * Selects the public key by the file's key id.
 *
 * An unknown id is refused rather than retried against every key held: a client
 * that tries them all accepts a file signed by a rotated-out key an attacker
 * recovered.
 */
export function verifyWithKeys(token: string, keys: Map<string, KeyObject>): Claims {
  const unverified = decode(token);

  const key = keys.get(unverified.keyId);
  if (!key) {
    throw new LicenseFileError(
      `license was signed by key "${unverified.keyId}", which this build does not trust`,
      "unknown_key",
    );
  }
  return verify(token, key);
}

/** True once the file is past its check-in time: keep running, refresh in the background. */
export function needsRevalidation(claims: Claims, now: Date): boolean {
  return claims.revalidateAfter !== 0 && Math.floor(now.getTime() / 1000) > claims.revalidateAfter;
}

/**
 * Entitlement to releases published now. A perpetual license with lapsed
 * maintenance keeps running but stops receiving updates.
 */
export function maintenanceActive(claims: Claims, now: Date): boolean {
  return claims.maintenanceExpiresAt === 0 || Math.floor(now.getTime() / 1000) <= claims.maintenanceExpiresAt;
}
