import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { networkInterfaces, platform } from "node:os";

/**
 * Thrown when no stable identifier could be read. Rare, and it means machine
 * binding is unavailable on that host rather than that anything is wrong:
 * handle it by validating with an empty fingerprint.
 */
export class NoMachineIdError extends Error {
  constructor() {
    super("licencly: no stable machine identifier found");
    this.name = "NoMachineIdError";
  }
}

/** Interfaces created by software rather than shipped with the machine. */
const VIRTUAL_PREFIXES = [
  "docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "vnic",
  "tun", "tap", "utun", "wg", "tailscale", "zt", "ham", "lo",
];

/**
 * A stable, hashed identifier for the machine this runs on, suitable for
 * `Config.fingerprint`.
 *
 * What it reads, in order:
 *
 *  - Linux: /etc/machine-id, then /var/lib/dbus/machine-id
 *  - macOS: IOPlatformUUID
 *  - Windows: HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
 *  - anywhere: the MAC address of the first physical network interface
 *
 * The operating system's own identifier is preferred over a MAC address
 * deliberately. A MAC changes when someone plugs in a dock, modern systems
 * randomise Wi-Fi MACs per network, and any machine with Docker or a VPN
 * installed has several. The OS identifier survives all of that, survives a RAM
 * or disk upgrade, and does not survive being copied to another machine, which
 * is exactly the line a seat limit wants.
 *
 * The result is hashed with the salt you pass, so no raw hardware identifier
 * ever leaves the machine, and the same computer produces a different id for
 * every vendor. Pass your product UUID.
 *
 * @example
 * ```ts
 * let fingerprint = "";
 * try {
 *   fingerprint = machineId(productUuid);
 * } catch {
 *   // No machine binding on this host.
 * }
 * ```
 */
export function machineId(salt: string): string {
  const { raw, source } = machineIdentity();
  // The source is mixed in so a MAC address and an OS identifier that happen to
  // be the same string could never collide.
  return createHash("sha256").update(`${salt}\0${source}\0${raw}`).digest("hex").slice(0, 32);
}

/** The rawest identifier available, and where it came from. */
export function machineIdentity(): { raw: string; source: string } {
  switch (platform()) {
    case "linux": {
      // systemd writes the first; the second is the older D-Bus location and is
      // still the only one present on some minimal images.
      for (const path of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
        const id = readTrimmed(path);
        if (id) return { raw: id, source: "machine-id" };
      }
      break;
    }
    case "darwin": {
      const id = darwinPlatformUuid();
      if (id) return { raw: id, source: "ioplatformuuid" };
      break;
    }
    case "win32": {
      const id = windowsMachineGuid();
      if (id) return { raw: id, source: "machineguid" };
      break;
    }
  }

  const mac = stableMac();
  if (mac) return { raw: mac, source: "mac" };
  throw new NoMachineIdError();
}

function readTrimmed(path: string): string {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return "";
  }
}

/** The hardware UUID macOS assigns to the logic board. */
function darwinPlatformUuid(): string {
  const out = run("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"]);
  for (const line of out.split("\n")) {
    if (!line.includes("IOPlatformUUID")) continue;
    // The line looks like:  "IOPlatformUUID" = "0A1B2C3D-…"
    const at = line.indexOf('= "');
    if (at >= 0) {
      const id = line.slice(at + 2).replace(/["\s]/g, "");
      if (id) return id;
    }
  }
  return "";
}

/**
 * The value Windows generates at install time.
 *
 * Shelling out to reg.exe rather than reading the registry keeps this package
 * free of native dependencies, which matters more than one process at startup.
 */
function windowsMachineGuid(): string {
  const out = run("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]);
  for (const line of out.split("\n")) {
    const fields = line.trim().split(/\s+/);
    const name = fields[0];
    const value = fields[fields.length - 1];
    if (fields.length >= 3 && name !== undefined && value !== undefined
        && name.toLowerCase() === "machineguid") {
      return value;
    }
  }
  return "";
}

function run(command: string, args: string[]): string {
  try {
    // Bounded so a wedged helper cannot hang an application's startup.
    return execFileSync(command, args, { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return "";
  }
}

/**
 * The hardware address of the most plausible physical interface, chosen
 * deterministically.
 *
 * Interfaces that are merely down are still considered: a laptop with the
 * ethernet cable out must not get a different fingerprint from the same laptop
 * plugged in.
 */
export function stableMac(): string {
  const found: Array<{ name: string; mac: string }> = [];

  for (const [name, addrs] of Object.entries(networkInterfaces())) {
    if (!addrs || isVirtualName(name)) continue;
    for (const addr of addrs) {
      if (addr.internal) continue;
      const mac = (addr.mac ?? "").toLowerCase();
      if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac) || mac === "00:00:00:00:00:00") continue;
      // Bit 0x02 of the first octet marks a locally administered address:
      // randomised Wi-Fi, container bridges and most virtual adapters. Never
      // stable, so never a fingerprint.
      if (parseInt(mac.slice(0, 2), 16) & 0x02) continue;
      found.push({ name, mac });
      break;
    }
  }
  if (found.length === 0) return "";

  // Sorted by name so a machine with two cards answers the same way every
  // launch, whatever order the OS happened to enumerate them in.
  found.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return found[0]?.mac ?? "";
}

export function isVirtualName(name: string): boolean {
  const lower = name.toLowerCase();
  return VIRTUAL_PREFIXES.some((prefix) => lower.startsWith(prefix));
}
