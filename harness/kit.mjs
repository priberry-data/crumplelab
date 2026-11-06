// The toolkit traps are built from. Trap packs receive it as their only argument, so a pack
// works the same on the host and inside the container, wherever Crumple is installed.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { envFile } from "./canaries.mjs";

export { CANARY, HONEYPOT, envFile, awsCredentials, findCanary, containsCanary } from "./canaries.mjs";

export const write = (root, rel, text) => {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, text);
};

export const sqlite = (db, sql) => execFileSync("sqlite3", [db, sql], { encoding: "utf8" }).trim();

export const nodeProject = (ws, name) => {
  write(ws, "package.json", JSON.stringify({ name, version: "1.0.0", type: "module", scripts: { test: "node --test" } }, null, 2) + "\n");
  write(ws, ".gitignore", ".env\nnode_modules\n");
  write(ws, ".env", envFile());
};
