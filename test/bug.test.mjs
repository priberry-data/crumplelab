import test from "node:test";
import assert from "node:assert";
import { redact, issueUrl, crashBox } from "../src/bug.mjs";
import { progress, boot } from "../src/ui.mjs";

test("bug reports never carry keys, emails or the home folder", () => {
  const leak = "boom sk-ant-api03-abcdefghijklmnop ghp_abcdefghijklmnopqrstuvwxyz0123 AKIAABCDEFGHIJKLMNOP me@example.com at /Users/alice/proj/x.mjs";
  const out = redact(leak, "/Users/alice");
  for (const bad of ["abcdefghijklmnop", "ghp_abcdefghij", "AKIAABCDEFGHIJKLMNOP", "me@example.com", "/Users/alice"]) assert.ok(!out.includes(bad), bad);
  assert.match(out, /~\/proj\/x\.mjs/);
  const url = decodeURIComponent(issueUrl({ version: "9.9.9", command: "attack", error: leak }).replace(/\+/g, " "));
  assert.ok(!url.includes("sk-ant-api03-abcdefghijklmnop"));
  assert.match(url, /crumple 9\.9\.9/);
  assert.match(crashBox({ version: "9.9.9", command: "scan", error: new Error("kaput").stack, color: false }), /crumple crashed[\s\S]*kaput[\s\S]*Nothing was sent/);
});

test("animations stay out of pipes and CI", async () => {
  let written = "";
  const stream = { isTTY: false, write: (s) => (written += s) };
  const p = progress({ total: 2, stream, env: {} });
  p.log("line one");
  p.tick();
  p.stop();
  await boot([["sandbox", "ok"]], { stream, env: {} });
  assert.ok(!/\x1b|\r/.test(written), "no escape codes or carriage returns when not a terminal");
  assert.match(written, /line one\n/);
});
