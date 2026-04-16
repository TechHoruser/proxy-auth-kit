import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import readline from "readline";
import crypto from "crypto";
import yaml from "js-yaml";
import { generateNginxConf, type Config, type ServiceConfig } from "./lib/nginx-config.js";
import { generateAutheliaConf } from "./lib/authelia-config.js";

// ---------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------

const askQuestion = (query: string): Promise<string> => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) =>
    rl.question(query, (ans: string) => {
      rl.close();
      resolve(ans.trim());
    }),
  );
};

const runCommand = (
  command: string,
  options: any = { stdio: "inherit" },
): string => {
  try {
    return execSync(command, options).toString();
  } catch (error) {
    return "";
  }
};

// ---------------------------------------------------------------------------
// Authelia users_database.yml helpers
// ---------------------------------------------------------------------------

const getUsersFilePath = () =>
  path.resolve(process.cwd(), "authelia", "users_database.yml");

const readUsersYaml = (): string => {
  const usersPath = getUsersFilePath();
  if (!fs.existsSync(usersPath)) {
    throw new Error(`No se encontró el archivo de usuarios: ${usersPath}`);
  }
  return fs.readFileSync(usersPath, "utf8");
};

const writeUsersYaml = (content: string) => {
  const usersPath = getUsersFilePath();
  fs.writeFileSync(
    usersPath,
    content.endsWith("\n") ? content : `${content}\n`,
  );
};

const userHeaderRegex = /^  ([^:\s][^:]*)\s*:\s*$/;

const getUsernames = (usersYaml: string): string[] => {
  const usernames: string[] = [];
  const lines = usersYaml.split(/\r?\n/);
  for (const line of lines) {
    const match = line.match(userHeaderRegex);
    if (match) {
      usernames.push(match[1].trim());
    }
  }
  return usernames;
};

const findUserBlock = (
  usersYaml: string,
  username: string,
): { start: number; end: number; lines: string[] } | null => {
  const lines = usersYaml.split(/\r?\n/);
  const start = lines.findIndex(
    (line) => line.trim() === `${username}:` && line.startsWith("  "),
  );

  if (start === -1) return null;

  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (userHeaderRegex.test(lines[i])) {
      end = i;
      break;
    }
  }

  return { start, end, lines };
};

// ---------------------------------------------------------------------------
// User-group helpers
// ---------------------------------------------------------------------------

const getUserGroups = (usersYaml: string, username: string): string[] => {
  const userBlock = findUserBlock(usersYaml, username);
  if (!userBlock) return [];
  const blockLines = userBlock.lines.slice(userBlock.start, userBlock.end);
  const groupsLineIdx = blockLines.findIndex((l) => l.trim() === "groups:");
  if (groupsLineIdx === -1) return [];
  const groups: string[] = [];
  for (let i = groupsLineIdx + 1; i < blockLines.length; i++) {
    const m = blockLines[i].match(/^\s*-\s+(.+)$/);
    if (m) groups.push(m[1].trim());
    else break;
  }
  return groups;
};

const setUserGroups = (usersYaml: string, username: string, groups: string[]): string => {
  const userBlock = findUserBlock(usersYaml, username);
  if (!userBlock) throw new Error(`Usuario '${username}' no encontrado.`);
  const blockLines = userBlock.lines.slice(userBlock.start, userBlock.end);
  const groupsLineIdx = blockLines.findIndex((l) => l.trim() === "groups:");
  let newBlockLines: string[];
  if (groupsLineIdx !== -1) {
    let groupsEnd = groupsLineIdx + 1;
    while (groupsEnd < blockLines.length && /^\s*-\s+/.test(blockLines[groupsEnd])) {
      groupsEnd++;
    }
    newBlockLines = [
      ...blockLines.slice(0, groupsLineIdx),
      ...blockLines.slice(groupsEnd),
    ];
  } else {
    newBlockLines = [...blockLines];
  }
  if (groups.length > 0) {
    while (newBlockLines.length > 0 && newBlockLines[newBlockLines.length - 1].trim() === "") {
      newBlockLines.pop();
    }
    newBlockLines.push("    groups:");
    for (const g of groups) {
      newBlockLines.push(`      - ${g}`);
    }
  }
  const nextLines = [
    ...userBlock.lines.slice(0, userBlock.start),
    ...newBlockLines,
    ...userBlock.lines.slice(userBlock.end),
  ];
  return nextLines.join("\n");
};

const getAllGroupsFromUsers = (usersYaml: string): string[] => {
  const groups = new Set<string>();
  let inGroups = false;
  for (const line of usersYaml.split(/\r?\n/)) {
    if (line.trim() === "groups:") { inGroups = true; continue; }
    if (inGroups) {
      const m = line.match(/^\s*-\s+(.+)$/);
      if (m) groups.add(m[1].trim());
      else inGroups = false;
    }
  }
  return Array.from(groups).sort();
};

// ---------------------------------------------------------------------------
// TOTP helpers
// ---------------------------------------------------------------------------

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const normalizeBase32 = (value: string): string =>
  value.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");

const generateBase32Secret = (length = 32): string => {
  const random = crypto.randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += base32Alphabet[random[i] % base32Alphabet.length];
  }
  return result;
};

const decodeBase32 = (value: string): Buffer => {
  const clean = normalizeBase32(value);
  let bits = "";
  for (const char of clean) {
    const index = base32Alphabet.indexOf(char);
    if (index === -1) throw new Error(`Carácter base32 inválido: ${char}`);
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
};

const generateTotpCode = (
  secret: string,
  timeStep = 30,
  digits = 6,
): string => {
  const key = decodeBase32(secret);
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    10 ** digits;
  return code.toString().padStart(digits, "0");
};

const printOtpData = (username: string, secret: string) => {
  const otpCode = generateTotpCode(secret);
  console.log(`\nUsuario: ${username}`);
  console.log(`Clave OTP (manual): \x1b[36m${secret}\x1b[0m`);
  console.log(`Código OTP actual:  \x1b[33m${otpCode}\x1b[0m`);
  console.log(`\nIntroduce la clave manual en tu app OTP.`);
};

// ---------------------------------------------------------------------------
// Authelia helpers
// ---------------------------------------------------------------------------

const restartAuthelia = () => {
  console.log("ℹ️  Recargando Authelia para aplicar cambios...");
  runCommand("docker compose kill --signal=SIGUSR1 authelia");
};

const generateAutheliaPasswordHash = (password: string): string | null => {
  console.log("Generando hash seguro (Argon2)...");
  const hashCommand = `docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password "${password}"`;
  const output = runCommand(hashCommand, { stdio: "pipe" });
  const match = output.match(/Digest: (.*)/);
  return match ? match[1].trim() : null;
};

const extractNotificationBlocks = (content: string): string[] => {
  const blockRegex =
    /The following one-time code should only be used in the prompt displayed in your\s*\r?\nbrowser\.\s*\r?\n\s*\r?\n-{20,}\s*\r?\n\s*([^\r\n]+?)\s*\r?\n\s*-{20,}/g;
  const blocks: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = blockRegex.exec(content)) !== null) {
    const block = match[1].trim();
    if (block) blocks.push(block);
  }
  return blocks;
};

// ---------------------------------------------------------------------------
// Actions — User management
// ---------------------------------------------------------------------------

function listUsers() {
  console.log("\n--- Lista de Usuarios (Authelia) ---");
  let usersYaml = "";
  try {
    usersYaml = readUsersYaml();
  } catch (error: any) {
    console.error(`❌ ${error.message}`);
    return;
  }
  const usernames = getUsernames(usersYaml);
  if (usernames.length === 0) {
    console.log("ℹ️  No hay usuarios definidos.");
    return;
  }
  usernames.forEach((username, index) => {
    console.log(`${index + 1}. ${username}`);
  });
}

async function addUser() {
  console.log("\n--- Añadir Nuevo Usuario ---");
  const username = await askQuestion("Nombre de usuario: ");
  if (!username) return;
  const password = await askQuestion("Contraseña: ");
  if (!password) return;
  const email =
    (await askQuestion("Email (opcional, p.ej: user@local.com): ")) ||
    `${username}@local.com`;

  const hash = generateAutheliaPasswordHash(password);
  if (!hash) {
    console.error("❌ No se pudo generar el hash de la contraseña.");
    return;
  }

  let usersYaml = "";
  try {
    usersYaml = readUsersYaml();
  } catch (error: any) {
    console.error(`❌ ${error.message}`);
    return;
  }

  if (getUsernames(usersYaml).includes(username)) {
    console.warn(`⚠️  El usuario '${username}' ya existe.`);
    return;
  }

  const userEntry = `
  ${username}:
    displayname: "${username}"
    password: "${hash}"
    email: "${email}"
    groups:
      - users
`;
  writeUsersYaml(`${usersYaml.trimEnd()}${userEntry}`);
  console.log(`✅ Usuario '${username}' añadido.`);
  restartAuthelia();
}

async function updateUserPassword() {
  console.log("\n--- Cambiar Contraseña de Usuario ---");
  const username = await askQuestion("Usuario a actualizar: ");
  if (!username) return;

  let usersYaml = "";
  try {
    usersYaml = readUsersYaml();
  } catch (error: any) {
    console.error(`❌ ${error.message}`);
    return;
  }

  const userBlock = findUserBlock(usersYaml, username);
  if (!userBlock) {
    console.error(`❌ El usuario '${username}' no existe.`);
    return;
  }

  const password = await askQuestion("Nueva contraseña: ");
  if (!password) return;

  const hash = generateAutheliaPasswordHash(password);
  if (!hash) {
    console.error("❌ No se pudo generar el hash.");
    return;
  }

  const blockLines = userBlock.lines.slice(userBlock.start, userBlock.end);
  const passwordLineIndex = blockLines.findIndex((line) =>
    line.trim().startsWith("password:"),
  );

  if (passwordLineIndex === -1) {
    console.error(`❌ No se encontró el campo password para '${username}'.`);
    return;
  }

  blockLines[passwordLineIndex] = `    password: "${hash}"`;

  const nextLines = [
    ...userBlock.lines.slice(0, userBlock.start),
    ...blockLines,
    ...userBlock.lines.slice(userBlock.end),
  ];

  writeUsersYaml(nextLines.join("\n"));
  console.log(`✅ Contraseña actualizada para '${username}'.`);
  restartAuthelia();
}

async function deleteUser() {
  console.log("\n--- Eliminar Usuario ---");
  const username = await askQuestion("Usuario a eliminar: ");
  if (!username) return;

  let usersYaml = "";
  try {
    usersYaml = readUsersYaml();
  } catch (error: any) {
    console.error(`❌ ${error.message}`);
    return;
  }

  const userBlock = findUserBlock(usersYaml, username);
  if (!userBlock) {
    console.error(`❌ El usuario '${username}' no existe.`);
    return;
  }

  const confirm = await askQuestion(
    `Confirma eliminación de '${username}' (escribe "SI"): `,
  );
  if (confirm !== "SI") {
    console.log("Operación cancelada.");
    return;
  }

  const nextLines = [
    ...userBlock.lines.slice(0, userBlock.start),
    ...userBlock.lines.slice(userBlock.end),
  ];

  writeUsersYaml(nextLines.join("\n"));
  console.log(`✅ Usuario '${username}' eliminado.`);
  restartAuthelia();
}

function showLatestNotificationCodeFromContainer() {
  console.log("\n--- Último código one-time (Authelia) ---");

  const output = runCommand(
    "docker compose exec authelia cat /config/notifications.txt",
    { stdio: "pipe" },
  );
  if (!output.trim()) {
    console.error("❌ No se pudo leer notifications.txt desde el contenedor.");
    return;
  }

  const notificationBlocks = extractNotificationBlocks(output);
  if (notificationBlocks.length === 0) {
    console.log("ℹ️  No hay códigos en notifications.txt");
    return;
  }

  const latestBlock = notificationBlocks[notificationBlocks.length - 1];
  console.log("\n🔐 Código detectado:");
  console.log(`\x1b[33m${latestBlock}\x1b[0m`);
}

async function manageUserGroups(): Promise<void> {
  console.log("\n--- Gestionar grupos del usuario ---");
  let usersYaml = "";
  try {
    usersYaml = readUsersYaml();
  } catch (error: any) {
    console.error(`❌ ${error.message}`);
    return;
  }

  const usernames = getUsernames(usersYaml);
  if (usernames.length === 0) {
    console.log("ℹ️  No hay usuarios.");
    return;
  }
  usernames.forEach((u, i) => console.log(`  ${i + 1}. ${u}`));

  const username = await askQuestion("\nNombre del usuario: ");
  if (!username || !usernames.includes(username)) {
    console.error("❌ Usuario no encontrado.");
    return;
  }

  const currentGroups = getUserGroups(usersYaml, username);
  console.log(
    `\nGrupos actuales de '${username}': ${currentGroups.length > 0 ? currentGroups.join(", ") : "(ninguno)"}`,
  );

  const allGroups = getAllGroupsFromUsers(usersYaml);
  if (allGroups.length > 0) {
    console.log(`Grupos existentes en el sistema: ${allGroups.join(", ")}`);
  }

  const newGroupsRaw = await askQuestion(
    `Nueva lista de grupos (separados por coma, Enter para no cambiar, "-" para quitar todos): `,
  );

  if (newGroupsRaw === "") {
    console.log("Sin cambios.");
    return;
  }

  const newGroups =
    newGroupsRaw === "-"
      ? []
      : newGroupsRaw.split(",").map((g) => g.trim()).filter(Boolean);

  const updatedYaml = setUserGroups(usersYaml, username, newGroups);
  writeUsersYaml(updatedYaml);
  console.log(
    `✅ Grupos de '${username}' actualizados: ${newGroups.length > 0 ? newGroups.join(", ") : "(ninguno)"}`,
  );
  restartAuthelia();
}

async function manageUsers() {
  while (true) {
    console.log("\n--- Gestión de Usuarios (Authelia) ---");
    console.log("1. Listar usuarios");
    console.log("2. Añadir usuario");
    console.log("3. Cambiar contraseña");
    console.log("4. Eliminar usuario");
    console.log("5. Gestionar grupos del usuario");
    console.log("6. Ver último código one-time (desde contenedor)");
    console.log("7. Volver al menú principal");
    console.log("---------------------------------------");

    const choice = await askQuestion("Selecciona una opción: ");

    switch (choice) {
      case "1":
        listUsers();
        break;
      case "2":
        await addUser();
        break;
      case "3":
        await updateUserPassword();
        break;
      case "4":
        await deleteUser();
        break;
      case "5":
        await manageUserGroups();
        break;
      case "6":
        showLatestNotificationCodeFromContainer();
        break;
      case "7":
        return;
      default:
        console.log("Opción no válida.");
    }
  }
}

// ---------------------------------------------------------------------------
// Actions — Logs
// ---------------------------------------------------------------------------

async function viewLogs() {
  while (true) {
    console.log("\n--- Ver Logs ---");
    console.log("1. Nginx (últimas 50 líneas)");
    console.log("2. Authelia (últimas 50 líneas)");
    console.log("3. Docker — todos los servicios (live, Ctrl+C para salir)");
    console.log("4. Volver al menú principal");
    console.log("--------------------------------");

    const choice = await askQuestion("Selecciona una opción: ");

    switch (choice) {
      case "1":
        console.log("\n--- Logs Nginx ---");
        runCommand("docker compose logs --tail=50 nginx");
        break;
      case "2":
        console.log("\n--- Logs Authelia ---");
        runCommand("docker compose logs --tail=50 authelia");
        break;
      case "3":
        console.log("\n--- Logs Docker en vivo (Ctrl+C para salir) ---");
        runCommand("docker compose logs -f --tail=20");
        break;
      case "4":
        return;
      default:
        console.log("Opción no válida.");
    }
  }
}

// ---------------------------------------------------------------------------
// Actions — Services
// ---------------------------------------------------------------------------

async function resetServices() {
  while (true) {
    console.log("\n--- Menú de Servicios ---");
    console.log("1. Reiniciar contenedores Docker");
    console.log("2. Renovación forzada de SSL (Certbot)");
    console.log("3. Volver al menú principal");
    console.log("---------------------------------");

    const subChoice = await askQuestion("Selecciona una opción: ");

    switch (subChoice) {
      case "1":
        console.log("Reiniciando contenedores Docker...");
        cleanupDockerState();
        runCommand("docker compose up -d");
        console.log("✅ Docker reiniciado.");
        break;

      case "2": {
        console.log("Iniciando renovación/expansión de SSL...");
        runCommand("docker compose stop nginx", { stdio: "ignore" });

        const domain = getDomain();
        if (domain === "<dominio>") {
          console.error("❌ No se encontró DOMAIN en el .env");
          break;
        }

        // Construir lista completa de dominios: raíz + auth + servicios actuales
        let config: Config;
        try {
          config = readConfig();
        } catch {
          config = { authelia: { totp_issuer: "", default_redirect: "auth" }, services: [] };
        }

        const certDomains = [
          domain,
          `auth.${domain}`,
          ...config.services.map((s) => `${s.subdomain}.${domain}`),
        ];
        const certDomainArgs = certDomains.map((d) => `-d ${d}`).join(" ");

        console.log(`Dominios: ${certDomains.join(", ")}`);

        const certDir = path.resolve(process.cwd(), "nginx", "certs");
        const certbotDataDir = path.resolve(process.cwd(), "nginx", "certbot-data");
        const certbotCommand =
          `docker run -it --rm --name certbot ` +
          `-v "${certDir}:/etc/letsencrypt" ` +
          `-v "${certbotDataDir}:/var/lib/letsencrypt" ` +
          `-p 80:80 ` +
          `certbot/certbot certonly --standalone ${certDomainArgs} ` +
          `--expand --force-renewal --non-interactive --agree-tos -m admin@${domain}`;

        runCommand(certbotCommand);
        console.log("✅ Certificados renovados/expandidos.");
        cleanupDockerState();
        runCommand("docker compose up -d");
        break;
      }

      case "3":
        return;

      default:
        console.log("Opción no válida.");
    }
  }
}

// ---------------------------------------------------------------------------
// Docker helpers
// ---------------------------------------------------------------------------

const cleanupDockerState = (): void => {
  // 1. Parar los servicios del proyecto actual
  runCommand("docker compose down", { stdio: "ignore" }, true);

  // 2. Eliminar por nombre cualquier contenedor huérfano de proyectos anteriores
  const composeFilePath = path.resolve(process.cwd(), "docker-compose.yml");
  if (fs.existsSync(composeFilePath)) {
    try {
      const composeConfig = yaml.load(fs.readFileSync(composeFilePath, "utf8")) as any;
      const containerNames: string[] = Object.values(composeConfig.services ?? {})
        .map((svc: any) => svc.container_name)
        .filter(Boolean);
      for (const name of containerNames) {
        runCommand(`docker rm -f ${name} 2>/dev/null || true`, { stdio: "ignore" }, true);
      }
    } catch { /* ignorar */ }
  }

  // 3. Eliminar la red para que compose la recree limpia
  runCommand("docker network rm proxy_net 2>/dev/null || true", { stdio: "ignore" }, true);
};

// ---------------------------------------------------------------------------
// Actions — Services (port ↔ subdomain mapping)
// ---------------------------------------------------------------------------

const CONFIG_PATH = path.resolve(process.cwd(), "config.yml");
const NGINX_CONF_PATH = path.resolve(process.cwd(), "nginx", "nginx.conf");
const AUTHELIA_CONF_PATH = path.resolve(process.cwd(), "authelia", "configuration.yml");

const readConfig = (): Config => {
  if (!fs.existsSync(CONFIG_PATH)) {
    const examplePath = path.resolve(process.cwd(), "config.example.yml");
    if (fs.existsSync(examplePath)) {
      fs.copyFileSync(examplePath, CONFIG_PATH);
    } else {
      throw new Error(`No se encontró config.yml ni config.example.yml en ${path.dirname(CONFIG_PATH)}`);
    }
  }
  const raw = yaml.load(fs.readFileSync(CONFIG_PATH, "utf8")) as Config;
  return { ...raw, services: raw.services ?? [] };
};

const writeConfig = (config: Config): void => {
  // Serializar como YAML preservando el encabezado de comentarios si existe
  const header =
    "# proxy-auth-kit — Configuración\n" +
    "# El dominio y el token de DuckDNS se definen en .env, no aquí.\n\n";
  fs.writeFileSync(CONFIG_PATH, header + yaml.dump(config, { lineWidth: 120 }));
};

const getDomain = (): string => {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return "<dominio>";
  const match = fs.readFileSync(envPath, "utf8").match(/^DOMAIN=["']?([^"'\n]+)["']?$/m);
  return match ? match[1] : "<dominio>";
};

const applyServiceChanges = (config: Config): void => {
  const domain = getDomain();
  const nginxDir = path.resolve(process.cwd(), "nginx");
  fs.mkdirSync(nginxDir, { recursive: true });
  fs.writeFileSync(NGINX_CONF_PATH, generateNginxConf(config, domain));
  console.log("✅ nginx.conf regenerado.");
  fs.writeFileSync(AUTHELIA_CONF_PATH, generateAutheliaConf(config, domain));
  console.log("✅ Authelia configuration.yml regenerado.");
  runCommand("docker compose exec nginx nginx -s reload 2>/dev/null || docker compose restart nginx");
  console.log("✅ Nginx recargado.");
  restartAuthelia();
};

const openUfwPort = (port: number): void => {
  const hasUfw = runCommand("which ufw", { stdio: "pipe" });
  if (hasUfw) {
    runCommand(`ufw allow from 172.16.0.0/12 to any port ${port} proto tcp`, { stdio: "ignore" });
  }
};

const closeUfwPort = (port: number, remainingPorts: number[]): void => {
  if (remainingPorts.includes(port)) return; // el puerto aún lo usa otro servicio
  const hasUfw = runCommand("which ufw", { stdio: "pipe" });
  if (hasUfw) {
    runCommand(`ufw delete allow from 172.16.0.0/12 to any port ${port} proto tcp`, { stdio: "ignore" });
  }
};

function listServices(config: Config, domain: string): void {
  if (config.services.length === 0) {
    console.log("ℹ️  No hay servicios configurados.");
    return;
  }
  console.log("");
  config.services.forEach((svc, i) => {
    const lock = svc.protected ? "🔒" : "🌐";
    const extras: string[] = [];
    if (svc.groups?.length) extras.push(`grupos: ${svc.groups.join(", ")}`);
    if (svc.cors_origin) extras.push(`cors: ${svc.cors_origin}`);
    if (svc.websocket) extras.push("ws");
    if (svc.public_paths?.length) extras.push(`public: ${svc.public_paths.join(", ")}`);
    const extrasStr = extras.length ? `  [${extras.join(" | ")}]` : "";
    console.log(`  ${i + 1}. ${lock} ${svc.subdomain}.${domain}  →  :${svc.port}${extrasStr}`);
  });
}

async function addService(): Promise<void> {
  console.log("\n--- Añadir servicio ---");
  const config = readConfig();
  const domain = getDomain();

  const subdomain = await askQuestion("Subdominio (ej: app): ");
  if (!subdomain) return;
  if (config.services.some((s) => s.subdomain === subdomain)) {
    console.error(`❌ Ya existe un servicio con el subdominio '${subdomain}'.`);
    return;
  }

  const portStr = await askQuestion("Puerto del host (ej: 3000): ");
  const port = Number(portStr);
  if (!port || isNaN(port)) { console.error("❌ Puerto inválido."); return; }

  const protectedAns = await askQuestion("¿Requiere login Authelia? [S/n]: ");
  const isProtected = protectedAns.toLowerCase() !== "n";

  const corsOrigin = await askQuestion("Subdominio de origen CORS (Enter para ninguno): ");
  const websocketAns = await askQuestion("¿Habilitar WebSocket? [s/N]: ");
  const websocket = websocketAns.toLowerCase() === "s" || undefined;

  let groups: string[] | undefined;
  if (isProtected) {
    const groupsRaw = await askQuestion(
      "Grupos con acceso (separados por coma, Enter para cualquier usuario autenticado): ",
    );
    groups = groupsRaw ? groupsRaw.split(",").map((g) => g.trim()).filter(Boolean) : undefined;
  }

  const svc: ServiceConfig = {
    subdomain,
    port,
    protected: isProtected,
    ...(groups?.length && { groups }),
    ...(corsOrigin && { cors_origin: corsOrigin }),
    ...(websocket && { websocket: true }),
  };

  config.services.push(svc);
  writeConfig(config);
  openUfwPort(port);
  applyServiceChanges(config);

  console.log(`✅ Servicio '${subdomain}.${domain}' añadido.`);
  console.log(`⚠️  Si es un subdominio nuevo, añade el certificado SSL: opción Servicios → Renovar SSL.`);
}

async function editService(): Promise<void> {
  console.log("\n--- Editar servicio ---");
  const config = readConfig();
  const domain = getDomain();

  if (config.services.length === 0) { console.log("ℹ️  No hay servicios."); return; }
  listServices(config, domain);

  const idxStr = await askQuestion("\nNúmero del servicio a editar: ");
  const idx = Number(idxStr) - 1;
  if (isNaN(idx) || idx < 0 || idx >= config.services.length) {
    console.error("❌ Número inválido.");
    return;
  }

  const svc = config.services[idx];
  console.log(`\nEditando: ${svc.subdomain}.${domain} → :${svc.port}`);
  console.log("(Enter para mantener el valor actual)\n");

  const newSubdomain = await askQuestion(`Subdominio [${svc.subdomain}]: `);
  const newPortStr = await askQuestion(`Puerto [${svc.port}]: `);
  const newPort = newPortStr ? Number(newPortStr) : svc.port;
  if (isNaN(newPort)) { console.error("❌ Puerto inválido."); return; }

  const protectedAns = await askQuestion(`¿Protegido por Authelia? [${svc.protected ? "S/n" : "s/N"}]: `);
  const newProtected =
    protectedAns === ""
      ? svc.protected
      : protectedAns.toLowerCase() === "s";

  const corsOriginAns = await askQuestion(`CORS origin [${svc.cors_origin ?? "ninguno"}]: `);
  const newCorsOrigin = corsOriginAns === "" ? svc.cors_origin : (corsOriginAns === "-" ? undefined : corsOriginAns);

  const websocketAns = await askQuestion(`WebSocket [${svc.websocket ? "S/n" : "s/N"}]: `);
  const newWebsocket =
    websocketAns === ""
      ? svc.websocket
      : (websocketAns.toLowerCase() === "s" ? true : undefined);

  let newGroups: string[] | undefined = svc.groups;
  if (newProtected) {
    const currentGroupsStr = svc.groups?.length ? svc.groups.join(", ") : "cualquier usuario autenticado";
    const groupsAns = await askQuestion(
      `Grupos con acceso [${currentGroupsStr}] (Enter para no cambiar, "-" para quitar restricción): `,
    );
    if (groupsAns === "-") {
      newGroups = undefined;
    } else if (groupsAns !== "") {
      newGroups = groupsAns.split(",").map((g) => g.trim()).filter(Boolean);
    }
  } else {
    newGroups = undefined;
  }

  const oldPort = svc.port;
  config.services[idx] = {
    subdomain: newSubdomain || svc.subdomain,
    port: newPort,
    protected: newProtected,
    ...(newGroups?.length && { groups: newGroups }),
    ...(newCorsOrigin && { cors_origin: newCorsOrigin }),
    ...(newWebsocket && { websocket: true }),
    ...(svc.public_paths?.length && { public_paths: svc.public_paths }),
  };

  writeConfig(config);
  if (newPort !== oldPort) {
    openUfwPort(newPort);
    closeUfwPort(oldPort, config.services.map((s) => s.port));
  }
  applyServiceChanges(config);
  console.log("✅ Servicio actualizado.");
}

async function removeService(): Promise<void> {
  console.log("\n--- Eliminar servicio ---");
  const config = readConfig();
  const domain = getDomain();

  if (config.services.length === 0) { console.log("ℹ️  No hay servicios."); return; }
  listServices(config, domain);

  const idxStr = await askQuestion("\nNúmero del servicio a eliminar: ");
  const idx = Number(idxStr) - 1;
  if (isNaN(idx) || idx < 0 || idx >= config.services.length) {
    console.error("❌ Número inválido.");
    return;
  }

  const svc = config.services[idx];
  const confirm = await askQuestion(`Confirma eliminación de '${svc.subdomain}.${domain}' (escribe "SI"): `);
  if (confirm !== "SI") { console.log("Operación cancelada."); return; }

  const removedPort = svc.port;
  config.services.splice(idx, 1);
  writeConfig(config);
  closeUfwPort(removedPort, config.services.map((s) => s.port));
  applyServiceChanges(config);
  console.log(`✅ Servicio '${svc.subdomain}' eliminado.`);
}

async function manageProxyServices(): Promise<void> {
  while (true) {
    const config = readConfig();
    const domain = getDomain();

    console.log("\n--- Gestión de servicios proxy ---");
    listServices(config, domain);
    console.log("\n1. Añadir servicio");
    console.log("2. Editar servicio");
    console.log("3. Eliminar servicio");
    console.log("4. Volver al menú principal");
    console.log("----------------------------------");

    const choice = await askQuestion("Selecciona una opción: ");
    switch (choice) {
      case "1": await addService(); break;
      case "2": await editService(); break;
      case "3": await removeService(); break;
      case "4": return;
      default: console.log("Opción no válida.");
    }
  }
}

// ---------------------------------------------------------------------------
// Actions — PM2 service management
// ---------------------------------------------------------------------------

interface Pm2Process {
  name: string;
  pm_id: number;
  pm2_env: {
    status: "online" | "stopped" | "errored" | "launching" | string;
    cwd: string;
    pm_exec_path: string;
    pm_cwd: string;
  };
}

const pm2Available = (): boolean => {
  try {
    execSync("which pm2", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

const ensurePm2 = (): boolean => {
  if (pm2Available()) return true;
  console.log("⚠️  PM2 no está instalado. Intentando instalarlo globalmente...");
  try {
    execSync("npm install -g pm2", { stdio: "inherit" });
    return pm2Available();
  } catch {
    console.error("❌ No se pudo instalar PM2. Instálalo manualmente: npm install -g pm2");
    return false;
  }
};

const listPm2Processes = (): Pm2Process[] => {
  try {
    const output = execSync("pm2 jlist 2>/dev/null", { encoding: "utf8" }).trim();
    if (!output || output === "[]") return [];
    return JSON.parse(output) as Pm2Process[];
  } catch {
    return [];
  }
};

const printPm2List = (processes: Pm2Process[]): void => {
  if (processes.length === 0) {
    console.log("ℹ️  No hay procesos PM2 activos.");
    return;
  }
  console.log("");
  processes.forEach((p, i) => {
    const icon = p.pm2_env.status === "online" ? "🟢" : p.pm2_env.status === "errored" ? "🔴" : "🟡";
    const script = p.pm2_env.pm_exec_path.replace(p.pm2_env.pm_cwd + "/", "");
    console.log(`  ${i + 1}. ${icon} ${p.name.padEnd(20)} [${p.pm2_env.status}]  ${p.pm2_env.cwd}  →  ${script}`);
  });
};

const PKG_MANAGERS = ["npm", "pnpm", "yarn", "bun"];

const buildPm2StartCmd = (name: string, command: string, cwd: string): string => {
  // "npm run dev"    → pm2 start npm --name api --cwd /x -- run dev
  // "pnpm start"     → pm2 start pnpm --name api --cwd /x -- start
  // "node dist/x.js" → pm2 start dist/x.js --name api --cwd /x
  // "python3 main.py"→ pm2 start main.py --name ai --interpreter python3 --cwd /x
  const parts = command.trim().split(/\s+/);
  const exec = parts[0];
  const args = parts.slice(1);
  const base = `--name "${name}" --cwd "${cwd}"`;

  const isPkgManager = PKG_MANAGERS.some((pm) => exec === pm || exec.endsWith(`/${pm}`));
  if (isPkgManager) {
    // Package managers need their args passed after --
    return `pm2 start ${exec} ${base} -- ${args.join(" ")}`;
  }

  // node/python/bash: exec is the interpreter, first arg is the script
  const knownInterpreters = ["node", "python3", "python", "bash", "sh", "ruby", "php"];
  const isInterpreter = knownInterpreters.some((i) => exec === i || exec.endsWith(`/${i}`));
  if (isInterpreter && args.length > 0) {
    const [script, ...rest] = args;
    return `pm2 start ${script} ${base} --interpreter ${exec}${rest.length ? ` -- ${rest.join(" ")}` : ""}`;
  }

  // Direct script (e.g. dist/index.js)
  return `pm2 start ${exec} ${base}${args.length ? ` -- ${args.join(" ")}` : ""}`;
};

async function pm2Add(): Promise<void> {
  console.log("\n--- Añadir proceso PM2 ---");

  const name = await askQuestion("Nombre del servicio (ej: api): ");
  if (!name) return;

  const cwd = await askQuestion("Directorio del proyecto (ruta absoluta, ej: /var/www/api): ");
  if (!cwd || !fs.existsSync(cwd)) {
    console.error(`❌ El directorio '${cwd}' no existe.`);
    return;
  }

  const command = await askQuestion("Comando (ej: npm run start, pnpm dev, node dist/index.js): ");
  if (!command) return;

  const pm2Cmd = buildPm2StartCmd(name, command, cwd);
  runCommand(pm2Cmd);
  runCommand("pm2 save");
  console.log(`✅ Proceso '${name}' iniciado y guardado.`);
}

async function pm2Action(action: "restart" | "stop" | "delete"): Promise<void> {
  const labels: Record<typeof action, string> = {
    restart: "Reiniciar",
    stop: "Parar",
    delete: "Eliminar",
  };
  console.log(`\n--- ${labels[action]} proceso PM2 ---`);

  const processes = listPm2Processes();
  if (processes.length === 0) { console.log("ℹ️  No hay procesos PM2."); return; }
  printPm2List(processes);

  const idxStr = await askQuestion("\nNúmero del proceso: ");
  const idx = Number(idxStr) - 1;
  if (isNaN(idx) || idx < 0 || idx >= processes.length) {
    console.error("❌ Número inválido.");
    return;
  }

  const proc = processes[idx];

  if (action === "delete") {
    const confirm = await askQuestion(`Confirma eliminación de '${proc.name}' (escribe "SI"): `);
    if (confirm !== "SI") { console.log("Operación cancelada."); return; }
  }

  runCommand(`pm2 ${action} ${proc.name}`);
  if (action !== "stop") runCommand("pm2 save");
  console.log(`✅ Proceso '${proc.name}' ${action === "restart" ? "reiniciado" : action === "stop" ? "parado" : "eliminado"}.`);
}

async function pm2Logs(): Promise<void> {
  const processes = listPm2Processes();
  if (processes.length === 0) { console.log("ℹ️  No hay procesos PM2."); return; }
  printPm2List(processes);

  const idxStr = await askQuestion("\nNúmero del proceso (Enter para todos): ");
  const idx = Number(idxStr) - 1;
  const target = (!idxStr || isNaN(idx) || idx < 0 || idx >= processes.length)
    ? ""
    : processes[idx].name;

  console.log("(Ctrl+C para salir)");
  runCommand(`pm2 logs ${target} --lines 50`);
}

async function managePm2(): Promise<void> {
  if (!ensurePm2()) return;

  while (true) {
    const processes = listPm2Processes();
    console.log("\n--- Gestionar servicios PM2 ---");
    printPm2List(processes);
    console.log("\n1. Añadir servicio");
    console.log("2. Reiniciar servicio");
    console.log("3. Parar servicio");
    console.log("4. Eliminar servicio");
    console.log("5. Ver logs");
    console.log("6. Volver al menú principal");
    console.log("-------------------------------");

    const choice = await askQuestion("Selecciona una opción: ");
    switch (choice) {
      case "1": await pm2Add(); break;
      case "2": await pm2Action("restart"); break;
      case "3": await pm2Action("stop"); break;
      case "4": await pm2Action("delete"); break;
      case "5": await pm2Logs(); break;
      case "6": return;
      default: console.log("Opción no válida.");
    }
  }
}

// ---------------------------------------------------------------------------
// Main menu
// ---------------------------------------------------------------------------

async function main() {
  while (true) {
    console.log("\n=========================================");
    console.log("🛠️  PROXY-AUTH-KIT — Panel de Control");
    console.log("=========================================");
    console.log("1. Ver logs");
    console.log("2. Gestionar usuarios (Authelia)");
    console.log("3. Gestionar servicios proxy (subdominio ↔ puerto)");
    console.log("4. Gestionar servicios PM2");
    console.log("5. Gestionar Docker y SSL");
    console.log("6. Salir");
    console.log("=========================================");

    const choice = await askQuestion("Selecciona una opción: ");

    switch (choice) {
      case "1":
        await viewLogs();
        break;
      case "2":
        await manageUsers();
        break;
      case "3":
        await manageProxyServices();
        break;
      case "4":
        await managePm2();
        break;
      case "5":
        await resetServices();
        break;
      case "6":
        process.exit(0);
        break;
      default:
        console.log("Opción no válida.");
    }
  }
}

main().catch(console.error);
