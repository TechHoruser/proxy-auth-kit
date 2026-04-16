import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import yaml from 'js-yaml';
import argon2 from 'argon2';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT ?? 1234);
const PROJECT_ROOT = process.env.PROJECT_ROOT ?? path.resolve(__dirname, '../..');
const USERS_DB_PATH =
  process.env.USERS_DB_PATH ?? path.join(PROJECT_ROOT, 'authelia', 'users_database.yml');
const CONFIG_PATH = process.env.CONFIG_PATH ?? path.join(PROJECT_ROOT, 'config.yml');
const AUTHELIA_CONF_PATH = path.join(PROJECT_ROOT, 'authelia', 'configuration.yml');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UserEntry {
  displayname: string;
  password: string;
  email: string;
  groups: string[];
}

interface UsersDb {
  users: Record<string, UserEntry>;
}

interface ServiceConfig {
  subdomain: string;
  port: number;
  protected: boolean;
  cors_origin?: string;
  websocket?: boolean;
  public_paths?: string[];
  groups?: string[];
}

interface AppConfig {
  authelia: { totp_issuer: string; default_redirect?: string };
  services: ServiceConfig[];
}

// ---------------------------------------------------------------------------
// YAML DB helpers
// ---------------------------------------------------------------------------

function readDb(): UsersDb {
  const content = fs.readFileSync(USERS_DB_PATH, 'utf8');
  const parsed = yaml.load(content) as UsersDb;
  return { users: parsed?.users ?? {} };
}

function writeDb(db: UsersDb): void {
  const header = [
    '###############################################################',
    '#                     Users Database                          #',
    '###############################################################',
    '# Este archivo se gestiona con: npm run control o auth-admin',
    '# Para generar un hash de contraseña manualmente:',
    "#   docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password 'tucontraseña'",
    '',
    '',
  ].join('\n');
  fs.writeFileSync(USERS_DB_PATH, header + yaml.dump(db, { lineWidth: 120 }));
}

function readConfig(): AppConfig {
  const parsed = yaml.load(fs.readFileSync(CONFIG_PATH, 'utf8')) as AppConfig;
  return { ...parsed, services: parsed?.services ?? [] };
}

function writeConfig(config: AppConfig): void {
  const header =
    '# proxy-auth-kit — Configuración\n' +
    '# El dominio y el token de DuckDNS se definen en .env, no aquí.\n\n';
  fs.writeFileSync(CONFIG_PATH, header + yaml.dump(config, { lineWidth: 120 }));
}

function getDomain(): string {
  const envPath = path.join(PROJECT_ROOT, '.env');
  if (!fs.existsSync(envPath)) return '';
  const match = fs.readFileSync(envPath, 'utf8').match(/^DOMAIN=["']?([^"'\n]+)["']?$/m);
  return match ? match[1] : '';
}

function applyAutheliaConfig(config: AppConfig, domain: string): void {
  const rules: string[] = [];
  for (const svc of config.services) {
    if (!svc.protected) continue;
    const svcDomain = `${svc.subdomain}.${domain}`;
    if (svc.groups && svc.groups.length > 0) {
      const subjects = svc.groups.map((g) => `        - 'group:${g}'`).join('\n');
      rules.push(`    - domain: '${svcDomain}'\n      subject:\n${subjects}\n      policy: one_factor`);
    } else {
      rules.push(`    - domain: '${svcDomain}'\n      policy: one_factor`);
    }
  }
  const rulesBlock = rules.join('\n');

  fs.writeFileSync(
    AUTHELIA_CONF_PATH,
    `###############################################################
#                   Authelia Configuration                    #
# Generado automáticamente por proxy-auth-kit.               #
# No editar manualmente — usar: npm run control              #
###############################################################

theme: dark

server:
  address: "tcp://0.0.0.0:9091/"

log:
  level: info

authentication_backend:
  file:
    path: /config/users_database.yml
    watch: true

access_control:
  default_policy: deny${rulesBlock ? `\n  rules:\n${rulesBlock}` : ''}

session:
  cookies:
    - name: authelia_session
      domain: '${domain}'
      authelia_url: 'https://auth.${domain}/'
      expiration: 3600
      inactivity: 300

regulation:
  max_retries: 3
  find_time: 120
  ban_time: 300

storage:
  local:
    path: /data/db.sqlite3

notifier:
  filesystem:
    filename: /data/notifications.txt
`,
  );
}

function reloadAuthelia(): void {
  // SIGUSR1 recarga config y users_database sin reiniciar — las sesiones se preservan
  spawn('docker', ['compose', 'kill', '--signal=SIGUSR1', 'authelia'], {
    cwd: PROJECT_ROOT,
    stdio: 'ignore',
    detached: true,
  }).unref();
}

// ---------------------------------------------------------------------------
// Async error wrapper
// ---------------------------------------------------------------------------

const wrap =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) =>
    fn(req, res).catch(next);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.get('/api/me', (req, res) => {
  res.json({
    username: req.headers['remote-user'] ?? null,
    displayname: req.headers['remote-name'] ?? null,
    groups: String(req.headers['remote-groups'] ?? '')
      .split(',')
      .filter(Boolean),
  });
});

app.get('/api/users', (req, res) => {
  const db = readDb();
  const users = Object.entries(db.users).map(([username, u]) => ({
    username,
    displayname: u.displayname,
    email: u.email,
    groups: u.groups ?? [],
  }));
  res.json(users);
});

app.post(
  '/api/users',
  wrap(async (req, res) => {
    const { username, displayname, email, password, groups } = req.body as {
      username: string;
      displayname?: string;
      email?: string;
      password: string;
      groups?: string[];
    };
    if (!username || !password) {
      res.status(400).json({ error: 'username y password son obligatorios' });
      return;
    }
    if (!/^[a-z0-9_-]+$/.test(username)) {
      res.status(400).json({ error: 'username solo puede contener letras minúsculas, números, guiones y guiones bajos' });
      return;
    }
    const db = readDb();
    if (db.users[username]) {
      res.status(409).json({ error: `El usuario '${username}' ya existe` });
      return;
    }
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
    db.users[username] = {
      displayname: displayname || username,
      password: hash,
      email: email || `${username}@local.com`,
      groups: Array.isArray(groups) ? groups : [],
    };
    writeDb(db);
    reloadAuthelia();
    res.status(201).json({ username });
  }),
);

app.put('/api/users/:username', (req, res) => {
  const { username } = req.params;
  const { displayname, email, groups } = req.body as {
    displayname?: string;
    email?: string;
    groups?: string[];
  };
  const db = readDb();
  if (!db.users[username]) {
    res.status(404).json({ error: `Usuario '${username}' no encontrado` });
    return;
  }
  if (displayname !== undefined) db.users[username].displayname = displayname;
  if (email !== undefined) db.users[username].email = email;
  if (groups !== undefined) db.users[username].groups = Array.isArray(groups) ? groups : [];
  writeDb(db);
  reloadAuthelia();
  res.json({ username });
});

app.put(
  '/api/users/:username/password',
  wrap(async (req, res) => {
    const { username } = req.params;
    const { password } = req.body as { password: string };
    if (!password) {
      res.status(400).json({ error: 'password es obligatorio' });
      return;
    }
    const db = readDb();
    if (!db.users[username]) {
      res.status(404).json({ error: `Usuario '${username}' no encontrado` });
      return;
    }
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
    db.users[username].password = hash;
    writeDb(db);
    reloadAuthelia();
    res.json({ username });
  }),
);

app.delete('/api/users/:username', (req, res) => {
  const { username } = req.params;
  const db = readDb();
  if (!db.users[username]) {
    res.status(404).json({ error: `Usuario '${username}' no encontrado` });
    return;
  }
  delete db.users[username];
  writeDb(db);
  reloadAuthelia();
  res.json({ username });
});

app.get('/api/groups', (req, res) => {
  const db = readDb();
  const groupMap: Record<string, string[]> = {};
  for (const [username, user] of Object.entries(db.users)) {
    for (const group of user.groups ?? []) {
      if (!groupMap[group]) groupMap[group] = [];
      groupMap[group].push(username);
    }
  }
  const groups = Object.entries(groupMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, members]) => ({ name, members: members.sort() }));
  res.json(groups);
});

// ---------------------------------------------------------------------------
// Services routes
// ---------------------------------------------------------------------------

app.get('/api/services', (req, res) => {
  try {
    const config = readConfig();
    const domain = getDomain();
    res.json(
      config.services.map((svc) => ({
        subdomain: svc.subdomain,
        port: svc.port,
        protected: svc.protected,
        groups: svc.groups ?? [],
        url: domain ? `https://${svc.subdomain}.${domain}` : null,
      })),
    );
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/services/:subdomain/groups', (req, res) => {
  const { subdomain } = req.params;
  const { groups } = req.body as { groups: string[] };
  try {
    const config = readConfig();
    const svc = config.services.find((s) => s.subdomain === subdomain);
    if (!svc) {
      res.status(404).json({ error: `Servicio '${subdomain}' no encontrado` });
      return;
    }
    svc.groups = Array.isArray(groups) ? groups : [];
    writeConfig(config);
    const domain = getDomain();
    if (domain) applyAutheliaConfig(config, domain);
    reloadAuthelia();
    res.json({ subdomain });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log(`auth-admin escuchando en http://localhost:${PORT}`);
  console.log(`Users DB: ${USERS_DB_PATH}`);
});
