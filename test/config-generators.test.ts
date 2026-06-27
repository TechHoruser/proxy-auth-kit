import { test } from "node:test";
import assert from "node:assert/strict";
import yaml from "js-yaml";
import { generateAutheliaConf } from "../scripts/lib/authelia-config.js";
import { generateNginxConf, type Config } from "../scripts/lib/nginx-config.js";

const domain = "example.duckdns.org";

const baseConfig = (): Config => ({
  authelia: { totp_issuer: "MiApp", default_redirect: "web" },
  services: [
    { subdomain: "auth-admin", port: 1234, protected: true, groups: ["admins"] },
    { subdomain: "web", port: 3001, protected: true },
    { subdomain: "docs", port: 3002, protected: false },
  ],
});

test("Authelia: la config generada es YAML válido", () => {
  const out = generateAutheliaConf(baseConfig(), domain);
  const parsed = yaml.load(out) as any;
  assert.ok(parsed, "debe parsear");
  assert.equal(parsed.access_control.default_policy, "deny");
  assert.equal(parsed.authentication_backend.file.watch, true);
  assert.equal(parsed.session.cookies[0].domain, domain);
  assert.equal(parsed.session.cookies[0].authelia_url, `https://auth.${domain}/`);
});

test("Authelia: solo los servicios protegidos generan reglas", () => {
  const parsed = yaml.load(generateAutheliaConf(baseConfig(), domain)) as any;
  const ruleDomains = parsed.access_control.rules.map((r: any) => r.domain);
  assert.deepEqual(ruleDomains, [
    `auth-admin.${domain}`,
    `web.${domain}`,
  ]);
  assert.ok(!ruleDomains.includes(`docs.${domain}`), "docs es público, no debe tener regla");
});

test("Authelia: las reglas con grupos usan subject group:<grupo>", () => {
  const parsed = yaml.load(generateAutheliaConf(baseConfig(), domain)) as any;
  const adminRule = parsed.access_control.rules.find(
    (r: any) => r.domain === `auth-admin.${domain}`,
  );
  assert.deepEqual(adminRule.subject, ["group:admins"]);
  assert.equal(adminRule.policy, "one_factor");

  const webRule = parsed.access_control.rules.find(
    (r: any) => r.domain === `web.${domain}`,
  );
  assert.equal(webRule.subject, undefined, "sin grupos = cualquier usuario autenticado");
  assert.equal(webRule.policy, "one_factor");
});

test("Authelia: sin servicios no genera bloque rules (solo default deny)", () => {
  const parsed = yaml.load(
    generateAutheliaConf({ authelia: { totp_issuer: "X" }, services: [] }, domain),
  ) as any;
  assert.equal(parsed.access_control.default_policy, "deny");
  assert.equal(parsed.access_control.rules, undefined);
});

test("Nginx: incluye server_name para cada subdominio + auth + raíz", () => {
  const out = generateNginxConf(baseConfig(), domain);
  assert.match(out, new RegExp(`server_name auth\\.${domain.replace(/\./g, "\\.")};`));
  assert.match(out, new RegExp(`server_name web\\.${domain.replace(/\./g, "\\.")};`));
  assert.match(out, new RegExp(`server_name docs\\.${domain.replace(/\./g, "\\.")};`));
});

test("Nginx: los servicios protegidos llevan auth_request; los públicos no", () => {
  const out = generateNginxConf(baseConfig(), domain);
  // El orden de bloques es: auth-admin, web, docs. Aislamos cada uno por sus límites.
  const webStart = out.indexOf(`server_name web.${domain}`);
  const docsStart = out.indexOf(`server_name docs.${domain}`);
  const webBlock = out.slice(webStart, docsStart);
  const docsBlock = out.slice(docsStart);

  assert.match(webBlock, /auth_request \/authelia\/auth_verify;/);
  assert.ok(
    !docsBlock.includes("auth_request /authelia/auth_verify;"),
    "docs es público y no debe requerir auth",
  );
});

test("Nginx: default_redirect ausente cae al portal auth (no genera 'undefined')", () => {
  const cfg: Config = { authelia: { totp_issuer: "X" }, services: [] };
  const out = generateNginxConf(cfg, domain);
  assert.ok(!out.includes("undefined."), "no debe aparecer 'undefined.' en la config");
  assert.match(out, new RegExp(`return 302 https://auth\\.${domain.replace(/\./g, "\\.")}/;`));
});

test("Nginx: cors_origin genera cabeceras CORS para el origen indicado", () => {
  const cfg: Config = {
    authelia: { totp_issuer: "X", default_redirect: "web" },
    services: [{ subdomain: "api", port: 4000, protected: true, cors_origin: "web" }],
  };
  const out = generateNginxConf(cfg, domain);
  assert.match(out, new RegExp(`Access-Control-Allow-Origin' 'https://web\\.${domain.replace(/\./g, "\\.")}'`));
});
