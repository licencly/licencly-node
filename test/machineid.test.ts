import assert from "node:assert/strict";
import test from "node:test";

import { isVirtualName, machineId, machineIdentity, stableMac } from "../src/machineid.js";

test("machineId is stable and opaque", () => {
  let first: string;
  try {
    first = machineId("product-uuid");
  } catch {
    return; // No stable identifier on this host.
  }

  assert.equal(machineId("product-uuid"), first, "not stable across calls");
  assert.equal(first.length, 32);
  assert.match(first, /^[0-9a-f]{32}$/);

  // The raw identifier must not be recoverable from what we send. A vendor's
  // dashboard should never hold a hardware serial.
  const { raw } = machineIdentity();
  assert.ok(!first.includes(raw.toLowerCase()), "the raw identifier leaks into the fingerprint");
});

// Two vendors must not be able to recognise the same machine, or Licencly
// becomes a cross-product tracking network by accident.
test("machineId differs per salt", () => {
  let a: string;
  try {
    a = machineId("product-a");
  } catch {
    return;
  }
  assert.notEqual(a, machineId("product-b"));
});

test("virtual interfaces are excluded", () => {
  for (const name of ["docker0", "veth1a2b", "br-abc123", "virbr0", "vmnet8", "tun0", "utun3", "tailscale0", "lo"]) {
    assert.ok(isVirtualName(name), `${name} should be virtual`);
  }
  for (const name of ["eth0", "eno1", "enp3s0", "wlan0", "wlp2s0", "en0", "Ethernet"]) {
    assert.ok(!isVirtualName(name), `${name} should be physical`);
  }
});

test("a MAC candidate, when there is one, is universally administered", () => {
  const mac = stableMac();
  if (mac === "") return;
  assert.match(mac, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/);
  // Bit 0x02 marks a randomised or virtual address, which is never an identity.
  assert.equal(parseInt(mac.slice(0, 2), 16) & 0x02, 0);
});
