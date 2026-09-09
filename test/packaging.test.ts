import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The package has to be usable from CommonJS, not only from ESM.
//
// It was ESM-only, and Electron's main process is CommonJS, so
// `require("@licencly/sdk")` failed with ERR_REQUIRE_ESM before the first line
// of anyone's app ran. Electron desktop apps are named explicitly in the
// product's positioning, which made this the worst possible place to be
// unusable.
//
// Run against the built output rather than the source, because the bug was
// entirely in how the build was published: the code was fine.
function runIn(filename: string, source: string): string {
  const dir = mkdtempSync(join(tmpdir(), "licencly-packaging-"));
  try {
    // A package.json without "type", so the file extension decides how each
    // file is read. That is the shape of a default Electron project.
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t" }));

    // Linked into node_modules and imported by name, not by path. That is how a
    // consumer reaches it, and it is the only way the "exports" map is
    // consulted at all: a direct path import bypasses the very thing under
    // test.
    mkdirSync(join(dir, "node_modules", "@licencly"), { recursive: true });
    symlinkSync(pkg, join(dir, "node_modules", "@licencly", "sdk"), "dir");

    writeFileSync(join(dir, filename), source);
    return execFileSync(process.execPath, [join(dir, filename)], {
      encoding: "utf8",
      env: { ...process.env, NODE_PATH: "" },
    }).trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Compiled to build/test/, so the package root is two levels up. Resolved
// rather than hardcoded as a relative string, because a test that silently
// points at the wrong directory would pass for the wrong reason.
// Compiled to build/test/, so the package root is two levels up. Resolved
// rather than hardcoded, because a test quietly pointing at the wrong directory
// would pass for the wrong reason.
const pkg = new URL("../../", import.meta.url).pathname.replace(/\/$/, "");

test("require() works, which is what an Electron main process does", () => {
  const out = runIn(
    "main.cjs",
    `const { Outcome, VERSION, LicenclyClient } = require("@licencly/sdk");
     if (typeof LicenclyClient !== "function") throw new Error("no client");
     console.log(Outcome.Valid + " " + VERSION);`,
  );
  assert.match(out, /^valid \d+\.\d+\.\d+$/);
});

test("import still works", () => {
  const out = runIn(
    "main.mjs",
    `import { Outcome, VERSION, LicenclyClient } from "@licencly/sdk";
     if (typeof LicenclyClient !== "function") throw new Error("no client");
     console.log(Outcome.Valid + " " + VERSION);`,
  );
  assert.match(out, /^valid \d+\.\d+\.\d+$/);
});

test("both entry points report the same version", () => {
  const cjs = runIn("v.cjs", `console.log(require("@licencly/sdk").VERSION);`);
  const esm = runIn("v.mjs", `import { VERSION } from "@licencly/sdk"; console.log(VERSION);`);
  assert.equal(cjs, esm, "the two builds disagree about the version, so one is stale");
});
