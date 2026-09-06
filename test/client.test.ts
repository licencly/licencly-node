import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import { test } from "node:test";
import { sign as edSign } from "node:crypto";

import { MemoryCache } from "../src/cache.js";
import { LicenclyClient } from "../src/client.js";
import { Outcome } from "../src/decision.js";
import { ApiError, isNetworkError } from "../src/errors.js";
import { FORMAT_VERSION, PREFIX, publicKeyFromRaw, Status } from "../src/licensefile.js";

const KID = "test-key-1";
const NOW = new Date("2026-06-01T12:00:00Z");

interface Fixture {
  client: LicenclyClient;
  cache: MemoryCache;
  server: Server;
  url: string;
  calls: () => number;
  setClaims: (fn: (now: Date) => Record<string, unknown>) => void;
  setStatus: (code: number) => void;
  setNow: (d: Date) => void;
  close: () => Promise<void>;
  signWith: (priv: KeyObject, claims: Record<string, unknown>) => string;
}

function activeClaims(now: Date): Record<string, unknown> {
  const s = Math.floor(now.getTime() / 1000);
  return {
    lic: "license-uuid",
    // Every file the server issues names the license it is for, and the client
    // now checks it: a cache keyed on the product alone would otherwise answer
    // for whichever license was validated last.
    key: "KEY",
    prd: "product-uuid",
    st: Status.Active,
    seats: 5,
    used: 1,
    fp: "machine-abc",
    iat: s - 3600,
    exp: 0,
    mnt: 0,
    rev: s + 7 * 24 * 3600,
    grace: 7 * 24 * 3600,
  };
}

async function newFixture(): Promise<Fixture> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);

  let claimsFn = activeClaims;
  let statusCode = 0;
  let now = NOW;
  let calls = 0;

  const sign = (priv: KeyObject, claims: Record<string, unknown>): string => {
    const payload = Buffer.from(
      JSON.stringify({ ...claims, v: FORMAT_VERSION, kid: KID }),
    ).toString("base64url");
    const signed = `${PREFIX}.${payload}`;
    const sig = edSign(null, Buffer.from(signed, "ascii"), priv).toString("base64url");
    return `${signed}.${sig}`;
  };

  const server = createServer((_req, res) => {
    calls++;
    if (statusCode) {
      res.writeHead(statusCode, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { code: "seat_limit_reached", message: "no free seats" } }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ license: sign(privateKey, claimsFn(now)), status: "active" }));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const url = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;

  const cache = new MemoryCache();
  const client = new LicenclyClient({
    productUuid: "product-uuid",
    publicKeys: new Map([[KID, publicKeyFromRaw(rawPub)]]),
    fingerprint: "machine-abc",
    cache,
    baseUrl: url,
    retries: 0,
    now: () => now,
  });

  return {
    client,
    cache,
    server,
    url,
    calls: () => calls,
    setClaims: (fn) => (claimsFn = fn),
    setStatus: (c) => (statusCode = c),
    setNow: (d) => (now = d),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    signWith: sign,
  };
}

test("fetches once, then serves from cache without touching the network", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  let decision = await f.client.validate("KEY");
  assert.equal(decision.outcome, Outcome.Valid);
  assert.equal(decision.fromCache, false);
  assert.equal(f.calls(), 1);

  // Inside the revalidation window, so no network call at all. An app that
  // phones home on every launch is an app that fails to launch on a plane.
  decision = await f.client.validate("KEY");
  assert.equal(decision.outcome, Outcome.Valid);
  assert.equal(decision.fromCache, true);
  assert.equal(f.calls(), 1, "a second validate hit the network");
});

test("server down inside the grace window keeps working", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  await f.client.validate("KEY");
  await f.close();

  // Past the check-in time, inside grace.
  f.setNow(new Date(NOW.getTime() + 8 * 24 * 3600 * 1000));

  const decision = await f.client.validate("KEY");
  assert.equal(decision.outcome, Outcome.Valid, "an outage must not stop a paid license");
  assert.equal(decision.fromCache, true);
  assert.equal(decision.needsRevalidation, true);
});

test("past the grace window is stale", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  await f.client.validate("KEY");
  await f.close();

  f.setNow(new Date(NOW.getTime() + 20 * 24 * 3600 * 1000));

  const decision = await f.client.validate("KEY");
  assert.equal(decision.outcome, Outcome.Stale);
});

test("revocation takes effect on the next refresh", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  assert.equal((await f.client.validate("KEY")).outcome, Outcome.Valid);

  f.setClaims((now) => ({ ...activeClaims(now), st: Status.Revoked }));
  f.setNow(new Date(NOW.getTime() + 8 * 24 * 3600 * 1000));

  assert.equal((await f.client.validate("KEY")).outcome, Outcome.NotActive);
});

test("a file that fails verification is never cached", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  // A different key: the response is well-formed but untrusted.
  const other = generateKeyPairSync("ed25519");
  f.server.removeAllListeners("request");
  f.server.on("request", (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ license: f.signWith(other.privateKey, activeClaims(NOW)) }));
  });

  const decision = await f.client.validate("KEY");
  assert.equal(decision.outcome, Outcome.Invalid);

  const { file } = await f.cache.load();
  assert.equal(file, "", "an unverifiable file was written to the cache");
});

test("a large backward clock jump is rejected", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  await f.client.validate("KEY");
  f.setNow(new Date(NOW.getTime() - 90 * 24 * 3600 * 1000));

  assert.equal((await f.client.validate("KEY")).outcome, Outcome.Invalid);
});

test("api errors stay distinguishable from network errors", async (t) => {
  const f = await newFixture();
  t.after(() => f.close());

  f.setStatus(409);

  await assert.rejects(
    () => f.client.validate("KEY"),
    (err: unknown) => {
      assert.ok(err instanceof ApiError, `got ${String(err)}`);
      assert.ok(err.seatLimitReached, "a caller cannot tell the user to free a seat");
      assert.equal(isNetworkError(err), false);
      return true;
    },
  );
});

test("a network failure with no cache is reported as retryable", async () => {
  const f = await newFixture();
  await f.close();

  await assert.rejects(
    () => f.client.validate("KEY"),
    (err: unknown) => {
      assert.ok(isNetworkError(err), `got ${String(err)}, want a NetworkError`);
      return true;
    },
  );
});

test("a client that cannot verify anything is refused at construction", () => {
  assert.throws(() => new LicenclyClient({ productUuid: "", publicKeys: {} }));
  assert.throws(() => new LicenclyClient({ productUuid: "p", publicKeys: {} }));
});

// The cache is keyed on the product, so it will happily hold the previous
// license. Validating a different key must not answer with the old one: a
// customer upgrading from a trial to a paid key, or replacing a revoked key,
// would otherwise keep being told about the license they just stopped using.
test("a cached file for another license is not reused", async () => {
  const f = await newFixture();
  try {
    const first = await f.client.validate("KEY");
    assert.equal(first.outcome, Outcome.Valid);
    assert.equal(f.calls(), 1);

    // Same product, different key. The cached file is fresh, so the old
    // behaviour returned it without a single network call.
    const second = await f.client.validate("OTHER-KEY");
    assert.equal(f.calls(), 2, "must go to the server for a different license");
    assert.equal(second.fromCache, false);
  } finally {
    await f.close();
  }
});

test("offline with a cache for another license fails rather than lying", async () => {
  const f = await newFixture();
  try {
    await f.client.validate("KEY");
    await f.close(); // the server is now unreachable

    // Falling back to the cache here would report the wrong customer, the
    // wrong expiry and the wrong seat count. Failing is the lesser evil.
    await assert.rejects(() => f.client.validate("OTHER-KEY"), /could not reach the server/);
  } catch (err) {
    await f.close().catch(() => {});
    throw err;
  }
});
