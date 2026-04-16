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

function restartAuthelia(): void {
  spawn('docker', ['compose', 'restart', 'authelia'], {
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
    restartAuthelia();
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
  restartAuthelia();
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
    restartAuthelia();
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
  restartAuthelia();
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
