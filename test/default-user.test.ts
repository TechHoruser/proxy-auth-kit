import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { createRequire } from "node:module";
import yaml from "js-yaml";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
// argon2 vive en apps/auth-admin; lo resolvemos desde ahí sin añadirlo a la raíz.
const requireFromAuthAdmin = createRequire(
  path.join(repoRoot, "apps", "auth-admin", "server.ts"),
);
const argon2 = requireFromAuthAdmin("argon2");

test("el hash por defecto de admin corresponde a la contraseña 'authelia'", async () => {
  // El archivo real no se versiona; la plantilla es la fuente del usuario por defecto.
  const db = yaml.load(
    fs.readFileSync(path.join(repoRoot, "authelia", "users_database.example.yml"), "utf8"),
  ) as { users: Record<string, { password: string }> };

  const admin = db.users?.admin;
  assert.ok(admin, "debe existir el usuario admin por defecto");
  assert.match(admin.password, /^\$argon2id\$/, "debe ser un hash argon2id");
  assert.equal(
    await argon2.verify(admin.password, "authelia"),
    true,
    "admin / authelia debe validar (es la credencial que documenta el README y el setup)",
  );
});
