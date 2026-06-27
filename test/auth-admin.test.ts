import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import yaml from "js-yaml";

// El servidor lee rutas y flags de entorno al importarse, así que se configuran
// ANTES del import dinámico de la app.
let server: Server;
let baseURL: string;
let tmpDir: string;
let usersDbPath: string;
let configPath: string;
let autheliaConfPath: string;

const seedUsersDb = `users:
  admin:
    displayname: "Admin"
    password: "$argon2id$v=19$m=65536,t=3,p=4$ZwShPpuuFbQGMH2HZAT9mw$Kf4c8yEWMx5nPQC1IFBnf26NLVCpV/ik8apFjVpW13w"
    email: admin@localhost.com
    groups:
      - admins
`;

const seedConfig = `authelia:
  totp_issuer: "Test"
  default_redirect: "web"
services:
  - subdomain: web
    port: 3001
    protected: true
  - subdomain: docs
    port: 3002
    protected: false
`;

async function api(method: string, p: string, body?: unknown) {
  const res = await fetch(baseURL + p, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "authadmin-test-"));
  fs.mkdirSync(path.join(tmpDir, "authelia"), { recursive: true });
  usersDbPath = path.join(tmpDir, "authelia", "users_database.yml");
  configPath = path.join(tmpDir, "config.yml");
  autheliaConfPath = path.join(tmpDir, "authelia", "configuration.yml");
  fs.writeFileSync(usersDbPath, seedUsersDb);
  fs.writeFileSync(configPath, seedConfig);
  fs.writeFileSync(path.join(tmpDir, ".env"), 'DOMAIN="example.duckdns.org"\n');

  process.env.PROJECT_ROOT = tmpDir;
  process.env.USERS_DB_PATH = usersDbPath;
  process.env.CONFIG_PATH = configPath;
  process.env.AUTH_ADMIN_DISABLE_RELOAD = "1"; // sin docker en CI
  process.env.PORT = "0";

  const { app } = await import("../apps/auth-admin/server.ts");
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const addr = server.address();
  if (addr && typeof addr === "object") baseURL = `http://127.0.0.1:${addr.port}`;
});

after(() => {
  server?.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("GET /api/users devuelve el admin sembrado (sin exponer el hash)", async () => {
  const { status, data } = await api("GET", "/api/users");
  assert.equal(status, 200);
  assert.equal(data.length, 1);
  assert.equal(data[0].username, "admin");
  assert.deepEqual(data[0].groups, ["admins"]);
  assert.equal((data[0] as any).password, undefined, "no debe filtrar el hash");
});

test("POST /api/users crea un usuario y se persiste en el YAML", async () => {
  const { status } = await api("POST", "/api/users", {
    username: "jdoe",
    displayname: "John Doe",
    email: "jdoe@example.com",
    password: "Sup3rSecret!",
    groups: ["users"],
  });
  assert.equal(status, 201);

  const list = await api("GET", "/api/users");
  const jdoe = list.data.find((u: any) => u.username === "jdoe");
  assert.ok(jdoe, "jdoe debe existir");
  assert.deepEqual(jdoe.groups, ["users"]);

  // El hash escrito debe ser argon2id (lo que espera Authelia)
  const db = yaml.load(fs.readFileSync(usersDbPath, "utf8")) as any;
  assert.match(db.users.jdoe.password, /^\$argon2id\$/);
});

test("POST /api/users rechaza usernames inválidos (400)", async () => {
  const { status } = await api("POST", "/api/users", {
    username: "John Doe",
    password: "x",
  });
  assert.equal(status, 400);
});

test("POST /api/users rechaza duplicados (409)", async () => {
  const { status } = await api("POST", "/api/users", {
    username: "admin",
    password: "x",
  });
  assert.equal(status, 409);
});

test("PUT /api/users/:u actualiza grupos y displayname", async () => {
  const { status } = await api("PUT", "/api/users/jdoe", {
    displayname: "Johnny",
    groups: ["users", "devs"],
  });
  assert.equal(status, 200);
  const list = await api("GET", "/api/users");
  const jdoe = list.data.find((u: any) => u.username === "jdoe");
  assert.equal(jdoe.displayname, "Johnny");
  assert.deepEqual(jdoe.groups.sort(), ["devs", "users"]);
});

test("PUT /api/users/:u/password cambia el hash", async () => {
  const before = (yaml.load(fs.readFileSync(usersDbPath, "utf8")) as any).users.jdoe.password;
  const { status } = await api("PUT", "/api/users/jdoe/password", {
    password: "An0therPass!",
  });
  assert.equal(status, 200);
  const after = (yaml.load(fs.readFileSync(usersDbPath, "utf8")) as any).users.jdoe.password;
  assert.notEqual(before, after);
  assert.match(after, /^\$argon2id\$/);
});

test("GET /api/groups agrega miembros por grupo", async () => {
  const { status, data } = await api("GET", "/api/groups");
  assert.equal(status, 200);
  const devs = data.find((g: any) => g.name === "devs");
  assert.ok(devs && devs.members.includes("jdoe"));
});

test("GET /api/services lista servicios con su URL", async () => {
  const { status, data } = await api("GET", "/api/services");
  assert.equal(status, 200);
  const web = data.find((s: any) => s.subdomain === "web");
  assert.equal(web.url, "https://web.example.duckdns.org");
  assert.equal(web.protected, true);
});

test("PUT /api/services/:sub/groups actualiza reglas (endpoint antes roto)", async () => {
  const { status, data } = await api("PUT", "/api/services/web/groups", {
    groups: ["devs"],
  });
  assert.equal(status, 200, `esperaba 200, obtuve ${status}: ${JSON.stringify(data)}`);

  // config.yml se actualiza
  const cfg = yaml.load(fs.readFileSync(configPath, "utf8")) as any;
  const web = cfg.services.find((s: any) => s.subdomain === "web");
  assert.deepEqual(web.groups, ["devs"]);

  // configuration.yml de Authelia se regenera con la regla por grupo
  const autheliaConf = yaml.load(fs.readFileSync(autheliaConfPath, "utf8")) as any;
  const webRule = autheliaConf.access_control.rules.find(
    (r: any) => r.domain === "web.example.duckdns.org",
  );
  assert.deepEqual(webRule.subject, ["group:devs"]);
});

test("DELETE /api/users/:u elimina el usuario", async () => {
  const { status } = await api("DELETE", "/api/users/jdoe");
  assert.equal(status, 200);
  const list = await api("GET", "/api/users");
  assert.ok(!list.data.some((u: any) => u.username === "jdoe"));
});

test("DELETE /api/users/:u inexistente devuelve 404", async () => {
  const { status } = await api("DELETE", "/api/users/nope");
  assert.equal(status, 404);
});

test("GET /restart responde ok y dispara el reinicio de Authelia", async () => {
  const { status, data } = await api("GET", "/restart");
  assert.equal(status, 200);
  assert.equal(data.ok, true);
});

test("POST /restart también está soportado", async () => {
  const { status, data } = await api("POST", "/restart");
  assert.equal(status, 200);
  assert.equal(data.ok, true);
});
