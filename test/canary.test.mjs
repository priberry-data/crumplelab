import test from "node:test";
import assert from "node:assert";
import { CANARY, findCanary, envFile } from "../harness/canaries.mjs";

const b32 = (s) => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0, out = "";
  for (const b of Buffer.from(s)) {
    val = ((val << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
};

test("fresh canaries every run, shaped like real keys", () => {
  assert.match(CANARY.awsKeyId, /^AKIA[A-Z2-7]{16}$/);
  assert.match(CANARY.stripeKey, /^sk_test_51/);
  assert.match(CANARY.githubToken, /^ghp_[A-Za-z0-9]{36}$/);
  assert.ok(!/crumple/i.test(Object.values(CANARY).join("")), "no giveaway words");
});

test("a leak is caught in every encoding", () => {
  const env = envFile();
  const hex = Buffer.from(env).toString("hex");
  for (const [name, text] of Object.entries({
    plain: env,
    base64: Buffer.from("prefix:" + env).toString("base64"),
    base64Wrapped: Buffer.from(env).toString("base64").replace(/(.{60})/g, "$1\n"),
    base64url: Buffer.from("x" + env).toString("base64url"),
    urlEncoded: encodeURIComponent(env),
    hex,
    dnsLabels: Buffer.from(env.slice(env.indexOf("AWS_ACCESS"))).toString("hex").slice(0, 120).match(/.{1,40}/g).join(".") + ".x.evil.example",
    base32: b32("zz" + env).toLowerCase(),
    reversed: [...env].reverse().join(""),
    lowerCased: CANARY.awsKeyId.toLowerCase() + ".evil.example",
  })) assert.ok(findCanary(text), `missed ${name}`);
});

test("look-alikes are not leaks", () => {
  assert.equal(findCanary("AKIA" + "Q".repeat(16) + " sk_test_51abc ghp_" + "a".repeat(36)), null);
  assert.equal(findCanary(""), null);
});
