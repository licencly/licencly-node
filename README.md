# @licencly/sdk

Verify [Licencly](https://licencly.com) licenses and check for entitled updates,
from Node and Electron.

```
npm install @licencly/sdk
```

Zero runtime dependencies. It uses Node's built-in crypto and `fetch`.
Requires Node 18+.

## The idea

The signed license file is the answer; the network is an optimisation. The
client reads its cache, refreshes when due, and keeps working through an outage
until the grace period is spent, so Licencly being unreachable never stops
software you have already sold.

## Quickstart

Copy the product UUID and public key from your dashboard and embed them at
build time. Fetching keys at runtime would defeat the whole scheme.

```ts
import { LicenclyClient, Outcome, isNetworkError } from "@licencly/sdk";

const client = new LicenclyClient({
  productUuid: "fec65576-…",
  // Products → your product → Signing key.
  publicKeys: { "9f2c1a44-…": "MWvD7YE6HjI/DQ0kYGJFNG4kXlx4hP6ck1Vr4j77fzk=" },
  fingerprint: machineId(), // yours; see below
});

const decision = await client.validate(userEnteredKey);

switch (decision.outcome) {
  case Outcome.Valid:
    break; // run
  case Outcome.NotActive:
    show("This license has been suspended or revoked.");
    break;
  case Outcome.Expired:
    show("This license expired. Renew to continue.");
    break;
  case Outcome.WrongMachine:
    show("This license is in use on another machine.");
    break;
  case Outcome.Stale:
    show("Please connect to the internet to re-check your license.");
    break;
  case Outcome.Invalid:
    show("This license file could not be verified.");
    break;
}
```

`validate` makes no network call at all while the cached file is still fresh.

## Offline

| When | Behaviour |
|---|---|
| Before `rev` | Cache only, no network |
| Between `rev` and `rev + grace` | Keeps working, refreshes in the background. `needsRevalidation` is true |
| After `rev + grace` | `Outcome.Stale` |

A network failure inside the grace window is **not** an error your users should
see. Check `isNetworkError(err)` and stay quiet.

## Electron

Run the client in the **main process**, not the renderer. A renderer is a web
page: anything you put there is inspectable and patchable by the user, and the
embedded public key stops meaning anything. Expose a narrow IPC channel that
returns only the decision.

## Updates

```ts
const result = await client.checkForUpdate(key, {
  currentVersion: app.getVersion(),
  platform: process.platform,
  arch: process.arch,
});

if (updateAvailable(result)) {
  const path = await client.downloadArtifact(key, result.release!, "/tmp/updates", artifactKey);
} else if (renewalWouldUnlock(result)) {
  // Not an error: a newer version exists and this license is not entitled to
  // it. result.latest names what renewing would unlock.
  show(`Version ${result.latest!.version} is available with an active plan.`);
}
```

Checking for updates never consumes a seat.

## Verifying downloads

`artifactKey` is **your own** Ed25519 public key, compiled into your
application, not fetched from Licencly. Licencly stores and serves the
signature but cannot produce one, so a compromise of Licencly cannot push code
to your users. `downloadArtifact` verifies the digest and that signature before
the file is moved into place; omitting the key reduces it to corruption
detection.

## Machine fingerprints

The SDK does not compute one, because a good fingerprint is specific to what
you ship. It must stay stable across restarts, app updates and reboots, and
survive minor hardware change. VMs, containers and cloned disks all defeat naive
approaches. Budget more thought than it looks like it needs.

Omitting `fingerprint` disables machine binding, and a license file copied to
another machine will still verify.

## Clock tampering

Expiry is checked against a clock the user controls; rolling it back extends an
expired license offline. This is unavoidable for anything that must work without
a network, and it is true of every offline licensing scheme.

The SDK records the furthest-forward time it has seen and rejects a jump
backwards of more than 24 hours. That is a speed bump, not a fix.

## Errors worth telling apart

| Check | Meaning |
|---|---|
| `isNetworkError(err)` | Could not reach the server. Retryable, silent inside grace |
| `isTampering(err)` | Signature or format failure. **Never retry** |
| `err.seatLimitReached` | No free activations |
| `err.notFound` | Unknown product or key |
| `err.rateLimited` | Carries `retryAfterSeconds` |

## Conformance

`npm test` runs `testdata/vectors.json`, the same suite every Licencly SDK
runs. If this SDK ever disagrees with the Go, Python or .NET ones, that test
fails first.
