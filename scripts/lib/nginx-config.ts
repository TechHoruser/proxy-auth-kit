// Shared nginx config generator — usado por setup.ts y control.ts

export interface ServiceConfig {
  subdomain: string;
  port: number;
  protected: boolean;
  cors_origin?: string;
  websocket?: boolean;
  public_paths?: string[];
  groups?: string[];
}

export interface Config {
  authelia: { totp_issuer: string; default_redirect?: string };
  services: ServiceConfig[];
}

// ---------------------------------------------------------------------------
// Blocks
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
        set $authelia_backend http://authelia:9091;
        proxy_pass $authelia_backend/api/authz/auth-request;
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

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export const generateNginxConf = (config: Config, domain: string): string => {
  const allSubdomains = [
    domain,
    ...config.services.map((s) => `${s.subdomain}.${domain}`),
    `auth.${domain}`,
  ].join(" ");

  const serviceBlocks = config.services
    .map((svc) => generateServiceBlock(svc, domain))
    .join("\n");

  // Si no se define default_redirect, el dominio raíz va al portal de Authelia.
  const defaultRedirect = config.authelia.default_redirect || "auth";

  return `worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;

    # Resolver interno de Docker — permite que nginx resuelva hostnames de contenedores
    # en tiempo de petición en lugar de al arrancar (evita el error "host not found in upstream")
    resolver 127.0.0.11 valid=10s ipv6=off;

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
            set $authelia_backend http://authelia:9091;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_pass $authelia_backend;
        }
    }
${serviceBlocks}
}
`;
};
