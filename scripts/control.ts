import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import readline from "readline";
import crypto from "crypto";

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
  console.log("ℹ️  Reiniciando Authelia para aplicar cambios...");
  runCommand("docker compose restart authelia");
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

async function manageUsers() {
  while (true) {
    console.log("\n--- Gestión de Usuarios (Authelia) ---");
    console.log("1. Listar usuarios");
    console.log("2. Añadir usuario");
    console.log("3. Cambiar contraseña");
    console.log("4. Eliminar usuario");
    console.log("5. Ver último código one-time (desde contenedor)");
    console.log("6. Volver al menú principal");
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
        showLatestNotificationCodeFromContainer();
        break;
      case "6":
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
        runCommand("docker compose down && docker compose up -d");
        console.log("✅ Docker reiniciado.");
        break;

      case "2": {
        console.log("Iniciando renovación forzada de SSL...");
        runCommand("docker compose stop nginx", { stdio: "ignore" });

        const envPath = path.resolve(process.cwd(), ".env");
        if (!fs.existsSync(envPath)) {
          console.error("❌ No se encontró el archivo .env");
          break;
        }

        const envContent = fs.readFileSync(envPath, "utf8");
        const domainMatch = envContent.match(/^DOMAIN=["']?([^"'\n]+)["']?$/m);
        const domain = domainMatch ? domainMatch[1] : "";

        if (!domain) {
          console.error("❌ No se encontró DOMAIN en el .env");
          break;
        }

        const certDir = path.resolve(process.cwd(), "nginx", "certs");
        const certbotDataDir = path.resolve(
          process.cwd(),
          "nginx",
          "certbot-data",
        );
        const certbotCommand =
          `docker run -it --rm --name certbot ` +
          `-v "${certDir}:/etc/letsencrypt" ` +
          `-v "${certbotDataDir}:/var/lib/letsencrypt" ` +
          `-p 80:80 ` +
          `certbot/certbot renew --standalone --non-interactive`;

        runCommand(certbotCommand);
        console.log("✅ Certificados renovados.");
        runCommand("docker compose up -d nginx");
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
// Main menu
// ---------------------------------------------------------------------------

async function main() {
  while (true) {
    console.log("\n=========================================");
    console.log("🛠️  PROXY-AUTH-KIT — Panel de Control");
    console.log("=========================================");
    console.log("1. Ver logs");
    console.log("2. Gestionar usuarios (Authelia)");
    console.log("3. Gestionar servicios (Docker, SSL)");
    console.log("4. Salir");
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
        await resetServices();
        break;
      case "4":
        process.exit(0);
        break;
      default:
        console.log("Opción no válida.");
    }
  }
}

main().catch(console.error);
