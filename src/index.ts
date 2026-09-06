/**
 * Verify Licencly licenses and check for entitled updates.
 *
 * @example
 * ```ts
 * const client = new LicenclyClient({
 *   productUuid: "fec65576-…",
 *   publicKeys: { "9f2c1a44-…": "MWvD7YE6HjI/DQ0kYGJFNG4kXlx4hP6ck1Vr4j77fzk=" },
 *   fingerprint: machineId(),
 * });
 *
 * const decision = await client.validate(userEnteredKey);
 * if (decision.outcome !== Outcome.Valid) {
 *   // decision.outcome says why
 * }
 * ```
 */

export { LicenclyClient, VERSION, type Config } from "./client.js";
export { Outcome, ok, type Decision, type OutcomeValue } from "./decision.js";
export {
  ApiError,
  NetworkError,
  isNetworkError,
  isTampering,
} from "./errors.js";
export {
  FORMAT_VERSION,
  LicenseFileError,
  PREFIX,
  Status,
  decode,
  maintenanceActive,
  needsRevalidation,
  publicKeyFromBase64,
  publicKeyFromRaw,
  verify,
  verifyWithKeys,
  type Claims,
  type LicenseStatus,
} from "./licensefile.js";
export {
  FileCache,
  MemoryCache,
  defaultCachePath,
  type Cache,
} from "./cache.js";
// downloadArtifact and DownloadOptions are not exported. The client method does
// the same job and already holds the base url, product uuid and user agent the
// standalone asks the caller to supply again; its only unique capability, a
// custom timeout, is now a parameter on the method. Two ways to do one thing
// would both be frozen at 1.0.
export {
  ArtifactError,
  UpdateOutcome,
  renewalWouldUnlock,
  updateAvailable,
  type Release,
  type UpdateQuery,
  type UpdateResult,
} from "./updates.js";
// Only machineId and its error. isVirtualName, machineIdentity and stableMac
// are how the fingerprint is derived, not something an application calls, and
// at 1.0 every exported name becomes a promise that cannot be withdrawn without
// a major version. The Go SDK never exported them; this matches it.
export { NoMachineIdError, machineId } from "./machineid.js";
