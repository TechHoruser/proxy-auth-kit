import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import https from "https";
import readline from "readline";
import crypto from "crypto";
import yaml from "js-yaml";
import { generateNginxConf, type Config } from "./lib/nginx-config.js";

// ---------------------------------------------------------------------------
// Setup state — persiste el progreso entre ejecuciones
// ---------------------------------------------------------------------------

const STATE_FILE = path.resolve(process.cwd(), ".setup-state");

interface SetupState {
  _help: string;
  steps: string[];
}

const loadState = (): SetupState => {
  if (fs.existsSync(STATE_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(STATE_FILE, "utf8")) as SetupState;
    } catch {
      return { _help: "", steps: [] };
    }
  }
  return {
    _help: "Progreso del setup. Elimina una entrada de 'steps' para forzar la re-ejecución de ese paso.",
    steps: [],
  };
};

const saveState = (state: SetupState): void => {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + "\n");
};

const isDone = (state: SetupState, step: string): boolean =>
  state.steps.includes(step);

const markDone = (state: SetupState, step: string): void => {
  if (!state.steps.includes(step)) {
    state.steps.push(step);
    saveState(state);
  }
};

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
  ignoreError: boolean = false,
): boolean => {
  console.log(`\n> ${command}`);
  try {
    execSync(command, options);
    return true;
  } catch (error) {
    console.error(`⚠️  Fallo ejecutando: ${command}`);
    if (!ignoreError) {
      process.exit(1);
    }
    return false;
  }
};

const generateSecret = () => crypto.randomBytes(32).toString("hex");

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=========================================");
  console.log("🚀 proxy-auth-kit — Setup inicial");
  console.log("=========================================");

  const state = loadState();
  const pending = (step: string) => {
    if (isDone(state, step)) {
      console.log(`\n⏭️  Paso '${step}' ya completado — saltando.`);
      return false;
    }
    return true;
  };

  // 0. Detectar contenedores con nombres en conflicto (incluyendo los de proyectos anteriores)
  const composeFilePath = path.resolve(process.cwd(), "docker-compose.yml");
  const conflictingContainers: string[] = [];

  if (fs.existsSync(composeFilePath)) {
    try {
      const composeConfig = yaml.load(fs.readFileSync(composeFilePath, "utf8")) as any;
      const containerNames: string[] = Object.values(composeConfig.services ?? {})
        .map((svc: any) => svc.container_name)
        .filter(Boolean);

      for (const name of containerNames) {
        const id = execSync(
          `docker ps -aq --filter name=^${name}$ 2>/dev/null`,
          { encoding: "utf8" },
        ).trim();
        if (id) conflictingContainers.push(name);
      }
    } catch { /* ignorar si docker no está disponible */ }
  }

  if (conflictingContainers.length > 0) {
    console.log(`\n⚠️  Contenedores con nombres en conflicto: ${conflictingContainers.join(", ")}`);
    const answer = await askQuestion("¿Eliminarlos para continuar el setup? [S/n]: ");
    if (answer.toLowerCase() !== "n") {
      for (const name of conflictingContainers) {
        runCommand(`docker rm -f ${name}`, { stdio: "inherit" }, true);
      }
    } else {
      console.warn("⚠️  Continuando sin eliminarlos — puede haber conflictos de nombres al levantar.");
    }
  }

  // 1. Cargar config.yml (crearlo desde config.example.yml si no existe)
  const configPath = path.resolve(process.cwd(), "config.yml");
  if (!fs.existsSync(configPath)) {
    const examplePath = path.resolve(process.cwd(), "config.example.yml");
    if (fs.existsSync(examplePath)) {
      fs.copyFileSync(examplePath, configPath);
      console.log("ℹ️  config.yml creado desde config.example.yml. Edítalo si necesitas ajustar la configuración.");
    } else {
      console.error("❌ No se encontró config.yml ni config.example.yml en el directorio actual.");
      process.exit(1);
    }
  }
  const rawConfig = yaml.load(fs.readFileSync(configPath, "utf8")) as Config;
  const config: Config = { ...rawConfig, services: rawConfig.services ?? [] };

  // 2. Cargar .env (siempre, aunque el paso 'env' ya esté hecho)
  const envPath = path.resolve(process.cwd(), ".env");
  let envVariables: Record<string, string> = {};

  if (fs.existsSync(envPath)) {
    const envFile = fs.readFileSync(envPath, "utf8");
    envFile.split("\n").forEach((line) => {
      const match = line.match(/^([^#=][^=]*)=(.*)$/);
      if (match) {
        envVariables[match[1].trim()] = match[2].trim().replace(/^"(.*)"$/, "$1");
      }
    });
  }

  // — Paso env ---------------------------------------------------------------
  if (pending("env")) {
    if (!envVariables["DOMAIN"]) {
      envVariables["DOMAIN"] = await askQuestion(
        "Introduce tu dominio DuckDNS (ej: miapp.duckdns.org): ",
      );
    }
    if (!envVariables["TOKEN"]) {
      envVariables["TOKEN"] = await askQuestion(
        "Introduce tu token de DuckDNS: ",
      );
    }

    const DOMAIN = envVariables["DOMAIN"];
    envVariables["AUTHELIA_TOTP_ISSUER"] = config.authelia.totp_issuer;

    if (!envVariables["AUTHELIA_JWT_SECRET"]) {
      console.log("Generando AUTHELIA_JWT_SECRET...");
      envVariables["AUTHELIA_JWT_SECRET"] = generateSecret();
    }
    if (!envVariables["AUTHELIA_SESSION_SECRET"]) {
      console.log("Generando AUTHELIA_SESSION_SECRET...");
      envVariables["AUTHELIA_SESSION_SECRET"] = generateSecret();
    }
    if (!envVariables["AUTHELIA_STORAGE_ENCRYPTION_KEY"]) {
      console.log("Generando AUTHELIA_STORAGE_ENCRYPTION_KEY...");
      envVariables["AUTHELIA_STORAGE_ENCRYPTION_KEY"] = generateSecret();
    }

    const envContent = Object.entries(envVariables)
      .map(([k, v]) => `${k}="${v}"`)
      .join("\n");
    fs.writeFileSync(envPath, envContent + "\n");
    console.log("✅ .env guardado.");
    markDone(state, "env");
  }

  process.env = { ...process.env, ...envVariables };
  const DOMAIN = envVariables["DOMAIN"];
  const TOKEN = envVariables["TOKEN"];

  // — Paso nginx_conf --------------------------------------------------------
  if (pending("nginx_conf")) {
    console.log(`\n[1/5] Generando nginx.conf para dominio: ${DOMAIN}...`);
    const nginxDir = path.resolve(process.cwd(), "nginx");
    fs.mkdirSync(nginxDir, { recursive: true });
    const nginxConf = generateNginxConf(config, DOMAIN);
    fs.writeFileSync(path.join(nginxDir, "nginx.conf"), nginxConf);
    console.log(
      `✅ nginx.conf generado con ${config.services.length} servicio(s) + auth.`,
    );
    markDone(state, "nginx_conf");
  }

  // — Paso duckdns -----------------------------------------------------------
  if (pending("duckdns")) {
    console.log(`\n[2/5] Actualizando IP en DuckDNS para ${DOMAIN}...`);
    const duckDnsUrl = `https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=`;

    await new Promise<void>((resolve, reject) => {
      https
        .get(duckDnsUrl, (res: any) => {
          let data = "";
          res.on("data", (chunk: any) => (data += chunk));
          res.on("end", () => {
            if (data.trim() === "OK") {
              console.log("✅ IP actualizada en DuckDNS.");
              resolve();
            } else {
              console.error(`❌ Respuesta inesperada de DuckDNS: ${data}`);
              reject(new Error("DuckDNS update failed"));
            }
          });
        })
        .on("error", (e: any) => {
          console.error(`❌ Error de red: ${e.message}`);
          reject(e);
        });
    });

    markDone(state, "duckdns");
  }

  // — Paso ufw ---------------------------------------------------------------
  let ufwExists = false;

  if (pending("ufw")) {
    console.log(`\n[3/5] Configurando firewall (UFW)...`);
    ufwExists = runCommand("which ufw", { stdio: "ignore" }, true);

    if (!ufwExists) {
      console.log("⚠️ 'ufw' no encontrado. Intentando instalar...");
      const hasApt = runCommand("which apt-get", { stdio: "ignore" }, true);
      if (hasApt) {
        const installed = runCommand(
          "sudo apt-get update && sudo apt-get install -y ufw",
          { stdio: "inherit" },
          true,
        );
        if (installed) {
          ufwExists = runCommand("which ufw", { stdio: "ignore" }, true);
        }
      }
    }

    if (ufwExists) {
      runCommand("ufw --force reset", { stdio: "ignore" }, true);
      runCommand("ufw default deny incoming", { stdio: "ignore" }, true);
      runCommand("ufw default allow outgoing", { stdio: "ignore" }, true);
      runCommand("ufw allow 22/tcp", { stdio: "ignore" }, true);
      runCommand("ufw allow 80/tcp", { stdio: "ignore" }, true);
      runCommand("ufw allow 443/tcp", { stdio: "ignore" }, true);

      const DOCKER_SUBNET = "172.16.0.0/12";
      const servicePorts = config.services.map((s) => s.port);
      for (const port of servicePorts) {
        runCommand(
          `ufw allow from ${DOCKER_SUBNET} to any port ${port} proto tcp`,
          { stdio: "ignore" },
          true,
        );
      }

      runCommand("ufw --force enable", { stdio: "ignore" }, true);
      console.log(
        `✅ UFW configurado. Puertos públicos: 22, 80 (temporal), 443. Docker→host: ${servicePorts.join(", ")}.`,
      );
    } else {
      console.warn(
        "⚠️ No se encontró 'ufw'. Asegúrate de abrir manualmente los puertos 22, 80 y 443.",
      );
    }

    markDone(state, "ufw");
  } else {
    ufwExists = runCommand("which ufw", { stdio: "ignore" }, true);
  }

  // — Paso certbot -----------------------------------------------------------
  if (pending("certbot")) {
    console.log(`\n[4/5] Generando certificado SSL con Certbot...`);
    runCommand("docker compose stop nginx", { stdio: "ignore" }, true);

    const certDomains = [
      DOMAIN,
      `auth.${DOMAIN}`,
      ...config.services.map((s) => `${s.subdomain}.${DOMAIN}`),
    ];
    const certDomainArgs = certDomains.map((d) => `-d ${d}`).join(" ");
    const certDir = path.resolve(process.cwd(), "nginx", "certs");
    const certbotDataDir = path.resolve(process.cwd(), "nginx", "certbot-data");

    const certbotCommand =
      `docker run -it --rm --name certbot ` +
      `-v "${certDir}:/etc/letsencrypt" ` +
      `-v "${certbotDataDir}:/var/lib/letsencrypt" ` +
      `-p 80:80 ` +
      `certbot/certbot certonly --standalone ${certDomainArgs} --expand --non-interactive --agree-tos -m admin@${DOMAIN}`;

    console.log(`Dominios: ${certDomains.join(", ")}`);
    const certOk = runCommand(certbotCommand, { stdio: "inherit" }, true);

    if (certOk) {
      console.log("✅ Certificado SSL generado.");
      // Puerto 80 permanece abierto: nginx lo necesita para redirigir HTTP → HTTPS
      markDone(state, "certbot");
    } else {
      console.warn(
        "⚠️ Certbot falló. Comprueba que los subdominios apuntan a este servidor. Continuando...",
      );
      // No se marca como completado — el próximo run lo reintentará.
    }
  }

  // — Docker (siempre) -------------------------------------------------------
  console.log(`\n[5/5] Levantando servicios Docker...`);
  // Eliminar contenedores y red huérfanos de proyectos compose anteriores
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
  runCommand("docker network rm proxy_net 2>/dev/null || true", { stdio: "ignore" }, true);
  runCommand("docker compose up -d");

  // ---------------------------------------------------------------------------
  // Resumen
  // ---------------------------------------------------------------------------
  console.log("\n=========================================");
  console.log("🎉 Setup completado.");
  console.log("=========================================");
  console.log(`\nURLs de acceso:`);
  console.log(`  Portal auth: https://auth.${DOMAIN}`);
  for (const svc of config.services) {
    const lock = svc.protected ? "🔒" : "🌐";
    console.log(`  ${lock} ${svc.subdomain}: https://${svc.subdomain}.${DOMAIN}`);
  }
  console.log(`\nUsuario por defecto: admin / authelia`);
  console.log(`Cambia la contraseña con: npm run control`);
  if (!isDone(state, "certbot")) {
    console.log(`\n⚠️  Certbot pendiente. Resuelve el problema con el puerto 80 y vuelve a ejecutar: npm run setup`);
  }
}

main().catch(console.error);
