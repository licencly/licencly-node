// The CommonJS build needs its own package.json saying so.
//
// The root package is "type": "module", and Node decides how to read a .js file
// from the nearest package.json above it. Without this marker every file in
// dist/cjs is read as ESM, `require()` fails with ERR_REQUIRE_ESM, and the
// second build might as well not exist.
//
// This is the whole reason the package was unusable from an Electron main
// process, which is CommonJS.
import { writeFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/cjs", { recursive: true });
writeFileSync("dist/cjs/package.json", JSON.stringify({ type: "commonjs" }, null, 2) + "\n");
console.log("marked dist/cjs as commonjs");
