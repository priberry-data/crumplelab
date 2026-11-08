import test from "node:test";
import assert from "node:assert";
import { siteScan } from "../src/site.mjs";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.${"s".repeat(20)}`;
const SB = "https://abcdefghijklmnopqrst.supabase.co";
const anon = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" });

// A fake vibe-coded app: a leaked Stripe key, the anon key, one open table and one locked one.
function fakeSite({ serviceRole = false } = {}) {
  const calls = [];
  const res = (status, text = "", headers = {}) => ({ status, url: undefined, headers: new Headers(headers), text: async () => text });
  const fetcher = async (url, opts) => {
    calls.push({ url, method: opts.method, headers: opts.headers });
    if (url === "https://app.example/") return { ...res(200, '<script type="module" src="/assets/index.js"></script>'), url };
    if (url === "https://app.example/assets/index.js")
      return res(200, `const s="${SB}",k="${anon}";const stripe="sk_live_${"a".repeat(24)}";${serviceRole ? `const admin="${jwt({ iss: "supabase", role: "service_role" })}";` : ""}\n//# sourceMappingURL=index.js.map`);
    if (url === "https://app.example/assets/index.js.map") return res(200);
    if (url === `${SB}/rest/v1/`) return res(200, JSON.stringify({ paths: { "/": {}, "/profiles": {}, "/posts": {}, "/rpc/do_thing": {} } }));
    if (url.startsWith(`${SB}/rest/v1/profiles`)) return res(206, "", { "content-range": "0-0/1234" });
    if (url.startsWith(`${SB}/rest/v1/posts`)) return res(200, "", { "content-range": "*/0" });
    return res(404);
  };
  return { fetcher, calls };
}

test("site: leaked keys and source maps are found from what every visitor downloads", async () => {
  const { fetcher, calls } = fakeSite({ serviceRole: true });
  const r = await siteScan("app.example", { fetcher });
  const titles = r.findings.map((f) => f.title);
  assert.ok(titles.some((t) => /live Stripe secret key/.test(t)));
  assert.ok(titles.some((t) => /service_role key is in the browser/.test(t)));
  assert.ok(titles.some((t) => /Source maps are public/.test(t)));
  assert.ok(titles.some((t) => /Database checks skipped/.test(t)), "without --mine the database is not touched");
  assert.ok(!calls.some((c) => c.url.includes("/rest/v1/")));
  assert.equal(r.grade, "F");
});

test("site --mine: counts readable rows with HEAD requests and never asks for rows", async () => {
  const { fetcher, calls } = fakeSite();
  const r = await siteScan("https://app.example", { fetcher, mine: true });
  const open = r.findings.filter((f) => /Anyone on the internet can read/.test(f.title));
  assert.equal(open.length, 1);
  assert.match(open[0].title, /1,234 rows of "profiles"/);
  assert.equal(open[0].severity, "critical", "a table of people is critical");
  const tableCalls = calls.filter((c) => /\/rest\/v1\/\w/.test(c.url));
  assert.ok(tableCalls.length === 2 && tableCalls.every((c) => c.method === "HEAD"));
  assert.deepEqual(r.supabase.readable, [{ table: "profiles", rows: 1234 }]);
});
