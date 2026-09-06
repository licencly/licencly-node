import type { Claims } from "./licensefile.js";
import { maintenanceActive, needsRevalidation, Status } from "./licensefile.js";

/** The result of evaluating a license. The set is fixed and shared by every Licencly SDK. */
export const Outcome = {
  /** Verified and inside its window. Run. */
  Valid: "valid",
  /** Signature or format failure. Tampering, not a network problem: refuse, do not retry. */
  Invalid: "invalid",
  /** Suspended, revoked, or expired by status. */
  NotActive: "not_active",
  /** Past its expiry date. */
  Expired: "expired",
  /** Issued to a different machine. */
  WrongMachine: "wrong_machine",
  /** The offline grace period is spent and the server could not be reached. */
  Stale: "stale",
} as const;

export type OutcomeValue = (typeof Outcome)[keyof typeof Outcome];

export interface Decision {
  outcome: OutcomeValue;
  /**
   * Populated whenever the signature verified, even for an expired or revoked
   * license, so an app can say *which* license expired.
   */
  claims?: Claims;
  /** True inside the grace window: keep running, refresh in the background. */
  needsRevalidation: boolean;
  /** No network call was made, or one failed and the cached file was used. */
  fromCache: boolean;
  /** Whether this license is entitled to releases published now. */
  maintenanceActive: boolean;
  error?: unknown;
}

/** The single check an application should gate on. */
export function ok(decision: Decision): boolean {
  return decision.outcome === Outcome.Valid;
}

/**
 * Maps a verification result onto an Outcome.
 *
 * Kept in one place so the mapping cannot drift between the cached and
 * freshly-fetched paths.
 */
export function evaluate(
  claims: Claims | undefined,
  error: unknown,
  now: Date,
  fingerprint: string,
  fromCache: boolean,
): Decision {
  if (!claims || error) {
    return {
      outcome: Outcome.Invalid,
      error,
      needsRevalidation: false,
      fromCache,
      maintenanceActive: false,
    };
  }

  const base = {
    claims,
    needsRevalidation: needsRevalidation(claims, now),
    fromCache,
    maintenanceActive: maintenanceActive(claims, now),
  };
  const seconds = Math.floor(now.getTime() / 1000);

  if (claims.status !== Status.Active) {
    return { ...base, outcome: Outcome.NotActive };
  }
  if (claims.expiresAt !== 0 && seconds > claims.expiresAt) {
    return { ...base, outcome: Outcome.Expired };
  }
  if (claims.fingerprint !== "" && fingerprint !== "" && claims.fingerprint !== fingerprint) {
    return { ...base, outcome: Outcome.WrongMachine };
  }
  if (claims.revalidateAfter !== 0 && seconds > claims.revalidateAfter + claims.graceSeconds) {
    return { ...base, outcome: Outcome.Stale };
  }
  return { ...base, outcome: Outcome.Valid };
}
