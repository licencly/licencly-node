import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";

/**
 * Stores the last good license file between runs. Without it, every launch
 * needs the network and the offline guarantee is worthless.
 */
export interface Cache {
  load(): Promise<{ file: string; highestSeen: Date }>;
  save(file: string, highestSeen: Date): Promise<void>;
  clear(): Promise<void>;
}

interface Envelope {
  /**
   * Stored verbatim. Re-serialising risks changing the exact bytes the
   * signature covers.
   */
  file: string;
  /** The furthest-forward time seen; a large jump back from it is tampering. */
  highest_seen: number;
}

const EMPTY = { file: "", highestSeen: new Date(0) };

/**
 * Stores the file in the user's data directory.
 *
 * Per-user and writable without privileges on purpose: an application that
 * needs admin rights to cache a license will not have them when it matters.
 */
export class FileCache implements Cache {
  constructor(private readonly path: string) {}

  async load(): Promise<{ file: string; highestSeen: Date }> {
    try {
      const raw = await readFile(this.path, "utf8");
      const env = JSON.parse(raw) as Envelope;
      return { file: env.file ?? "", highestSeen: new Date((env.highest_seen ?? 0) * 1000) };
    } catch {
      // A missing cache is the normal first-run state. A corrupt one is treated
      // as absent rather than invalid: telling a user their license is broken
      // because a disk hiccup truncated a file we can simply refetch would be
      // wrong.
      return EMPTY;
    }
  }

  async save(file: string, highestSeen: Date): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });

    const env: Envelope = { file, highest_seen: Math.floor(highestSeen.getTime() / 1000) };

    // Write and rename, so an interrupted save cannot leave a half-written
    // cache that reads as corrupt on next launch.
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(env), { mode: 0o600 });
    await rename(tmp, this.path);
  }

  async clear(): Promise<void> {
    await rm(this.path, { force: true });
  }
}

/** Holds the file for the process lifetime only. Useful in tests and short-lived jobs. */
export class MemoryCache implements Cache {
  private file = "";
  private highestSeen = new Date(0);

  async load() {
    return { file: this.file, highestSeen: this.highestSeen };
  }

  async save(file: string, highestSeen: Date) {
    this.file = file;
    this.highestSeen = highestSeen;
  }

  async clear() {
    this.file = "";
    this.highestSeen = new Date(0);
  }
}

/** An OS-appropriate per-user location for the cached license. */
export function defaultCachePath(productSlug: string): string {
  const name = `${sanitize(productSlug)}.license`;

  switch (platform()) {
    case "win32":
      return join(process.env["APPDATA"] ?? join(homedir(), "AppData", "Roaming"), "licencly", name);
    case "darwin":
      return join(homedir(), "Library", "Application Support", "licencly", name);
    default:
      return join(process.env["XDG_CONFIG_HOME"] ?? join(homedir(), ".config"), "licencly", name);
  }
}

function sanitize(value: string): string {
  const cleaned = value.replace(/[^a-zA-Z0-9_-]/g, "-").replace(/^-+|-+$/g, "");
  return cleaned || "license";
}
