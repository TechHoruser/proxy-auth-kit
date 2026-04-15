import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import https from "https";
import readline from "readline";
import crypto from "crypto";
import yaml from "js-yaml";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ServiceConfig {
  subdomain: string;
  port: number;
  protected: boolean;
  cors_origin?: string;
  websocket?: boolean;
  public_paths?: string[];
}

interface Config {
  authelia: { totp_issuer: string; default_redirect: string };
  services: ServiceConfig[];
}

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
// Nginx config generator
// ---------------------------------------------------------------------------

const sslBlock = (domain: string) => `
    ssl_certificate     /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;`;

const autheliaVerifyLocation = () => `
    location = /authelia/auth_verify {
        internal;
        proxy_pass http://authelia:9091/api/authz/auth-request;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header Connection "";
    }`;

const error401Location = (subdomain: string, domain: string) => `
    error_page 401 = @error401_${subdomain};
    location @error401_${subdomain} {
        return 302 https://auth.${domain}/?rd=$scheme://$http_host$request_uri;
    }`;

const proxyHeaders = (isProtected: boolean) => {
  const authHeaders = isProtected
    ? `
        auth_request /authelia/auth_verify;
        auth_request_set $user $upstream_http_remote_user;
        auth_request_set $groups $upstream_http_remote_groups;
        auth_request_set $name $upstream_http_remote_name;
        proxy_set_header Remote-User $user;
        proxy_set_header Remote-Groups $groups;
        proxy_set_header Remote-Name $name;`
    : "";
  return `${authHeaders}
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;`;
};

const generateServiceBlock = (svc: ServiceConfig, domain: string): string => {
  const corsOriginDomain = svc.cors_origin
    ? `https://${svc.cors_origin}.${domain}`
    : null;

  // Public paths that bypass auth (only meaningful when protected: true)
  const publicPathBlocks = (svc.public_paths ?? [])
    .map(
      (p) => `
    location ${p} {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://host.docker.internal:${svc.port}/;
    }`,
    )
    .join("");

  const websocketHeaders = svc.websocket
    ? `
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";`
    : "";

  const corsBlock = corsOriginDomain
    ? `
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '${corsOriginDomain}' always;
            add_header 'Access-Control-Allow-Credentials' 'true' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
`
    : "";

  const authVerify = svc.protected ? autheliaVerifyLocation() : "";
  const error401 = svc.protected ? error401Location(svc.subdomain, domain) : "";

  return `
    # =========================================================================
    # ${svc.subdomain}.${domain}${svc.protected ? " (protegido por Authelia)" : " (público)"}
    # =========================================================================
    server {
        listen 443 ssl;
        server_name ${svc.subdomain}.${domain};
${sslBlock(domain)}
${authVerify}
${error401}
${publicPathBlocks}
        location / {
${corsBlock}${proxyHeaders(svc.protected)}
${websocketHeaders}
            proxy_pass http://host.docker.internal:${svc.port}/;
        }
    }`;
};

const generateNginxConf = (config: Config, domain: string): string => {
  const allSubdomains = [
    domain,
    ...config.services.map((s) => `${s.subdomain}.${domain}`),
    `auth.${domain}`,
  ].join(" ");

  const serviceBlocks = config.services
    .map((svc) => generateServiceBlock(svc, domain))
    .join("\n");

  const defaultRedirect = config.authelia.default_redirect;

  return `worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;

    # Variables para cuando Nginx está detrás de un proxy
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Real-IP;
    real_ip_recursive on;

    # =========================================================================
    # HTTP → Redirigir todo a HTTPS
    # =========================================================================
    server {
        listen 80;
        server_name ${allSubdomains};
        return 301 https://$host$request_uri;
    }

    # =========================================================================
    # Dominio raíz → redirige al subdominio por defecto
    # =========================================================================
    server {
        listen 443 ssl;
        server_name ${domain};
${sslBlock(domain)}

        location = / {
            return 302 https://${defaultRedirect}.${domain}/;
        }

        location ~ ^/([^/]+)/?(.*)$ {
            return 302 https://$1.${domain}/$2$is_args$args;
        }
    }

    # =========================================================================
    # Portal Authelia
    # =========================================================================
    server {
        listen 443 ssl;
        server_name auth.${domain};
${sslBlock(domain)}

        location / {
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_pass http://authelia:9091/;
        }
    }
${serviceBlocks}
}
`;
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=========================================");
  console.log("🚀 proxy-auth-kit — Setup inicial");
  console.log("=========================================");

  // 1. Cargar config.yml
  const configPath = path.resolve(process.cwd(), "config.yml");
  if (!fs.existsSync(configPath)) {
    console.error("❌ No se encontró config.yml en el directorio actual.");
    process.exit(1);
  }
  const config = yaml.load(fs.readFileSync(configPath, "utf8")) as Config;

  // 2. Cargar / crear .env
  const envPath = path.resolve(process.cwd(), ".env");
  let envVariables: Record<string, string> = {};

  if (fs.existsSync(envPath)) {
    console.log(`Cargando variables desde ${envPath}`);
    const envFile = fs.readFileSync(envPath, "utf8");
    envFile.split("\n").forEach((line) => {
      const match = line.match(/^([^#=][^=]*)=(.*)$/);
      if (match) {
        envVariables[match[1].trim()] = match[2].trim().replace(/^"(.*)"$/, "$1");
      }
    });
  }

  // DOMAIN y TOKEN vienen del .env — pedir si faltan
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

  // Authelia settings desde config.yml (usan DOMAIN del .env)
  envVariables["AUTHELIA_TOTP_ISSUER"] = config.authelia.totp_issuer;
  envVariables["AUTHELIA_DEFAULT_REDIRECTION_URL"] =
    `https://${config.authelia.default_redirect}.${DOMAIN}/`;

  // 3. Generar secretos Authelia si no existen
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

  // 4. Guardar .env
  const envContent = Object.entries(envVariables)
    .map(([k, v]) => `${k}="${v}"`)
    .join("\n");
  fs.writeFileSync(envPath, envContent + "\n");
  process.env = { ...process.env, ...envVariables };
  console.log("✅ .env guardado.");

  // 5. Generar nginx/nginx.conf desde config.yml
  console.log(`\n[1/5] Generando nginx.conf para dominio: ${DOMAIN}...`);
  const nginxDir = path.resolve(process.cwd(), "nginx");
  fs.mkdirSync(nginxDir, { recursive: true });
  const nginxConf = generateNginxConf(config, DOMAIN);
  fs.writeFileSync(path.join(nginxDir, "nginx.conf"), nginxConf);
  console.log(
    `✅ nginx.conf generado con ${config.services.length} servicio(s) + auth.`,
  );

  const TOKEN = envVariables["TOKEN"];

  // 6. DuckDNS: actualizar IP
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

  // 7. UFW: configurar firewall
  console.log(`\n[3/5] Configurando firewall (UFW)...`);

  let ufwExists = runCommand("which ufw", { stdio: "ignore" }, true);

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
    runCommand("ufw allow 22/tcp", { stdio: "ignore" }, true);   // SSH
    runCommand("ufw allow 80/tcp", { stdio: "ignore" }, true);   // HTTP temporal (Let's Encrypt)
    runCommand("ufw allow 443/tcp", { stdio: "ignore" }, true);  // HTTPS

    // Permitir que Docker (Nginx) acceda a los servicios del host
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

  // 8. SSL: generar certificados con Certbot
  console.log(`\n[4/5] Generando certificado SSL con Certbot...`);

  // Parar nginx si está corriendo (libera el puerto 80)
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
    if (ufwExists) {
      runCommand("ufw delete allow 80/tcp", { stdio: "ignore" }, true);
      console.log("✅ Puerto 80 cerrado en el firewall.");
    }
  } else {
    console.warn(
      "⚠️ Certbot falló. Comprueba que los subdominios apuntan a este servidor. Continuando...",
    );
  }

  // 9. Levantar servicios Docker
  console.log(`\n[5/5] Levantando servicios Docker...`);
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
}

main().catch(console.error);
