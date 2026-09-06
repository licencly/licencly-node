/**
 * Errors a caller has to tell apart. Collapsing these into one type is the most
 * common way to make a licensing integration unsupportable: "it doesn't work"
 * means something different for each.
 */

/** Could not reach Licencly. Retryable, and inside the grace window not user-visible. */
export class NetworkError extends Error {
  constructor(readonly cause: unknown) {
    super(`licencly: could not reach the server: ${String(cause)}`);
    this.name = "NetworkError";
  }
}

/** A structured refusal from the server. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    /** Present on a 429. */
    readonly retryAfterSeconds?: number,
  ) {
    super(`licencly: ${message} (${code})`);
    this.name = "ApiError";
  }

  /**
   * Unknown product, unknown key, or a malformed one. The server deliberately
   * does not distinguish them: that would let anyone probe which keys are real.
   */
  get notFound(): boolean {
    return this.status === 404;
  }

  /**
   * In use on the maximum number of machines. Distinguished from notFound
   * because the holder has proved they own a real key and needs to be told to
   * free a seat.
   */
  get seatLimitReached(): boolean {
    return this.code === "seat_limit_reached";
  }

  get rateLimited(): boolean {
    return this.status === 429;
  }
}

export function isNetworkError(err: unknown): err is NetworkError {
  return err instanceof NetworkError;
}

/**
 * The license file failed verification. Never retry these: retrying obscures an
 * attack and fixes nothing.
 */
export function isTampering(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "name" in err &&
    (err as { name: string }).name === "LicenseFileError"
  );
}
