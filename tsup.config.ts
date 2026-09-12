import { defineConfig } from "tsup"

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2022",
    splitting: false,
    outExtension({ format }) {
      return { js: format === "cjs" ? ".cjs" : ".mjs" }
    },
  },
  {
    // the self-hosted browser bundle. An additional IIFE
    // artifact (window.OverturoVerify), served first-party by SdkController at
    // /sdk/verify/v1/verify.js — never vendored into app/javascript, never in
    // the application.js bundle. Minified; no sourcemap on the wire.
    entry: ["src/index.ts"],
    format: ["iife"],
    globalName: "OverturoVerify",
    minify: true,
    sourcemap: false,
    target: "es2022",
    splitting: false,
    clean: false, // the esm/cjs entry above owns clean:true — don't wipe its output
    outExtension() {
      return { js: ".global.js" }
    },
  },
])
