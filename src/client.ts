import type { KeyObject } from "node:crypto";

import { Cache, defaultCachePath, FileCache, MemoryCache } from "./cache.js";
import { type Decision, evaluate, Outcome } from "./decision.js";
import { ApiError, NetworkError } from "./errors.js";
import {
  type Claims,
  needsRevalidation,
  publicKeyFromBase64,
  verifyWithKeys,
} from "./licensefile.js";
import {
  type Release,
  type UpdateQuery,
  type UpdateResult,
  checkForUpdate,
  downloadArtifact,
} from "./updates.js";

/** Sent in the user agent, so a vendor's traffic is identifiable in support. */
export const VERSION = "1.0.1";

const DEFAULT_BASE_URL = "https://licencly.com";
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_RETRIES = 2;

/**
 * How far the clock may move backwards before it is treated as tampering
 * rather than an NTP correction or a timezone change.
 */
const CLOCK_SKEW_TOLERANCE_MS = 24 * 60 * 60 * 1000;

/**
 * Folds a license key the way the server does, so a cached file can be matched
 * against whatever the customer actually typed.
 *
 * Mirrors NormalizeKey server side: upper case, drop the grouping characters,
 * and map the look-alikes Crockford base32 leaves out. No checksum here; this
 * only ever compares two values, and rejecting a key is the server's job.
 */
function foldKey(key: string): string {
  let out = "";
  for (const ch of key.trim().toUpperCase()) {
    if (ch === "-" || ch === " " || ch === "\t" || ch === "_") continue;
    if (ch === "I" || ch === "L") out += "1";
    else if (ch === "O") out += "0";
    else out += ch;
  }
  return out;
}

export interface Config {
  /** Identifies your product. From the dashboard. */
  productUuid: string;

  /**
   * Maps a signing key id to its public key. Embed these at build time.
   * fetching them at runtime would defeat the entire scheme.
   *
   * Include retired keys as well as the active one: a license signed before a
   * rotation still verifies against the key it was signed with.
   */
  publicKeys: Record<string, string> | Map<string, KeyObject>;

  /**
   * Identifies this machine. Omitting it disables machine binding, which makes
   * the file usable anywhere it is copied.
   */
  fingerprint?: string;

  /** Persists the last good file. Defaults to a per-user file. */
  cache?: Cache;

  baseUrl?: string;
  timeoutMs?: number;
  retries?: number;

  /** Reported on activation so a vendor can recognise machines. Optional. */
  hostname?: string;
  platform?: string;
  appVersion?: string;

  /** Overrides the clock, for tests. */
  now?: () => Date;
}

interface ValidateResponse {
  license: string;
  status: string;
  seats: number;
  used: number;
}

/**
 * Verifies Licencly licenses and checks for entitled updates.
 *
 * The design in one sentence: the signed license file is the answer, and the
 * network is an optimisation. `validate` reads the cache, refreshes when due,
 * and keeps working through an outage until the grace period is spent, so
 * Licencly being unreachable never stops software you have already sold.
 */
export class LicenclyClient {
  private readonly keys: Map<string, KeyObject>;
  private readonly cache: Cache;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly now: () => Date;

  constructor(private readonly config: Config) {
    if (!config.productUuid) {
      throw new Error("licencly: productUuid is required");
    }

    this.keys =
      config.publicKeys instanceof Map
        ? config.publicKeys
        : new Map(
            Object.entries(config.publicKeys).map(([kid, encoded]) => [
              kid,
              publicKeyFromBase64(encoded),
            ]),
          );

    if (this.keys.size === 0) {
      throw new Error("licencly: at least one public key is required, or nothing can be verified");
    }

    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retries = config.retries ?? DEFAULT_RETRIES;
    this.now = config.now ?? (() => new Date());

    this.cache =
      config.cache ??
      (() => {
        try {
          return new FileCache(defaultCachePath(config.productUuid));
        } catch {
          // Falling back to memory rather than failing: an unusual home
          // directory should degrade the offline story, not break startup.
          return new MemoryCache();
        }
      })();
  }

  /**
   * Decides whether this machine may run.
   *
   * Refreshes from the server when the cached file is due, and falls back to
   * the cache whenever the server cannot be reached, so a Licencly outage does
   * not stop software that has already been sold. Never blocks on the network
   * while a usable cached file exists.
   *
   * The cache is keyed on the product, so it can hold a license other than the
   * one being validated. A cached file is only reused when its key claim
   * matches the key asked about and its fingerprint matches this machine;
   * otherwise the server is asked, because answering with a different
   * customer's license would be worse than failing.
   *
   * @throws when there is no usable cached file and the server cannot be
   * reached, which for a customer means a first run with no network.
   */
  async validate(licenseKey: string): Promise<Decision> {
    const now = this.now();
    const fingerprint = this.config.fingerprint ?? "";

    const { file: cached, highestSeen } = await this.cache.load();

    // A large jump backwards from the furthest time seen is not an NTP
    // correction. A speed bump rather than a fix: anyone who can set the clock
    // can also patch the binary.
    if (highestSeen.getTime() > 0 && now.getTime() + CLOCK_SKEW_TOLERANCE_MS < highestSeen.getTime()) {
      return {
        outcome: Outcome.Invalid,
        error: new Error("licencly: system clock moved backwards by more than 24 hours"),
        needsRevalidation: false,
        fromCache: true,
        maintenanceActive: false,
      };
    }

    let cacheAnswersThisKey = false;

    if (cached) {
      try {
        const claims = verifyWithKeys(cached, this.keys);

        // An absent key claim cannot be compared, so it counts as a match:
        // every file the server issues carries one.
        const claimKey = claims.key ?? "";
        cacheAnswersThisKey = claimKey === "" || foldKey(claimKey) === foldKey(licenseKey);

        const sameMachine =
          claims.fingerprint === "" || fingerprint === "" || claims.fingerprint === fingerprint;

        if (cacheAnswersThisKey && sameMachine && !needsRevalidation(claims, now)) {
          return evaluate(claims, undefined, now, fingerprint, true);
        }
      } catch {
        // Unverifiable, so refetch.
      }
    }

    let fetched: string;
    try {
      fetched = await this.fetch(licenseKey);
    } catch (err) {
      if (!cached || !cacheAnswersThisKey) {
        throw err;
      }
      return this.evaluateToken(cached, now, fingerprint, true);
    }

    const decision = this.evaluateToken(fetched, now, fingerprint, false);
    if (decision.claims) {
      const seen = now.getTime() > highestSeen.getTime() ? now : highestSeen;
      await this.cache.save(fetched, seen);
    }
    return decision;
  }

  /** Asks which release this license is entitled to. Never consumes a seat. */
  async checkForUpdate(licenseKey: string, query: UpdateQuery = {}): Promise<UpdateResult> {
    return checkForUpdate(
      (path) => this.request("GET", path),
      this.config.productUuid,
      licenseKey,
      query,
    );
  }

  /**
   * Downloads a release and verifies it before returning a path.
   *
   * @param artifactKey YOUR Ed25519 public key, compiled into this application
   * and not fetched from Licencly. Licencly stores and serves the signature but
   * cannot produce one, so a compromise of Licencly cannot push code to your
   * users. Omitting it reduces the check to corruption detection.
   * @param timeoutMs Bounds the download. Defaults to thirty minutes, which is
   * what the server allows; anything longer is a client the server has already
   * stopped waiting for.
   */
  async downloadArtifact(
    licenseKey: string,
    release: Release,
    destDir: string,
    artifactKey?: KeyObject,
    timeoutMs?: number,
  ): Promise<string> {
    return downloadArtifact({
      baseUrl: this.baseUrl,
      productUuid: this.config.productUuid,
      licenseKey,
      release,
      destDir,
      artifactKey,
      timeoutMs,
      userAgent: `licencly-node/${VERSION}`,
    });
  }

  /** Frees this machine's seat. */
  async deactivate(licenseKey: string): Promise<void> {
    await this.request("POST", "/v1/licenses/deactivate", {
      product: this.config.productUuid,
      key: licenseKey,
      fingerprint: this.config.fingerprint ?? "",
    });
    await this.cache.clear();
  }

  /** Removes the stored license. Exposed so support can say "run this". */
  async clearCache(): Promise<void> {
    await this.cache.clear();
  }

  private evaluateToken(token: string, now: Date, fingerprint: string, fromCache: boolean): Decision {
    let claims: Claims | undefined;
    let error: unknown;
    try {
      claims = verifyWithKeys(token, this.keys);
    } catch (err) {
      error = err;
    }
    return evaluate(claims, error, now, fingerprint, fromCache);
  }

  private async fetch(licenseKey: string): Promise<string> {
    const body: Record<string, string> = {
      product: this.config.productUuid,
      key: licenseKey,
    };
    if (this.config.fingerprint) {
      body["fingerprint"] = this.config.fingerprint;
      body["hostname"] = this.config.hostname ?? "";
      body["platform"] = this.config.platform ?? "";
      body["app_version"] = this.config.appVersion ?? "";
    }

    const raw = (await this.request("POST", "/v1/licenses/validate", body)) as ValidateResponse;
    if (!raw?.license) {
      throw new Error("licencly: the server returned no license file");
    }
    return raw.license;
  }

  private async request(method: string, path: string, body?: unknown): Promise<unknown> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff. Validate is idempotent, so retrying is safe.
        await sleep(2 ** (attempt - 1) * 200);
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      let response: Response;
      try {
        response = await globalThis.fetch(this.baseUrl + path, {
          method,
          headers: {
            "Content-Type": "application/json",
            "User-Agent": `licencly-node/${VERSION}`,
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (err) {
        lastError = new NetworkError(err);
        continue;
      } finally {
        clearTimeout(timer);
      }

      const text = await response.text();

      if (response.ok) {
        return text ? JSON.parse(text) : undefined;
      }

      const error = parseApiError(response, text);
      // 4xx is a decision, not a hiccup: retrying an invalid key just makes the
      // same answer arrive three times.
      if (response.status < 500) {
        throw error;
      }
      lastError = error;
    }

    throw lastError;
  }
}

function parseApiError(response: Response, text: string): ApiError {
  let code = "unexpected_error";
  let message = `request failed (${response.status})`;

  try {
    const envelope = JSON.parse(text) as { error?: { code?: string; message?: string } };
    if (envelope.error?.code) {
      code = envelope.error.code;
      message = envelope.error.message ?? message;
    }
  } catch {
    // Keep the defaults.
  }

  const retryAfter = response.headers.get("Retry-After");
  return new ApiError(
    response.status,
    code,
    message,
    retryAfter ? Number(retryAfter) : undefined,
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
