# proxy-auth-kit

Stack de reverse proxy con autenticación para VPS.
Nginx + Authelia + DuckDNS + SSL automático, todo configurado desde un solo archivo YAML.

## Qué hace

- Nginx como reverse proxy HTTPS con subdominios por servicio
- Authelia como portal de autenticación (login + TOTP opcional)
- Certificados SSL automáticos via Certbot + Let's Encrypt
- DNS dinámico via DuckDNS (actualización de IP en cada setup)
- Firewall UFW configurado automáticamente

## Arquitectura

```
Internet
   │ 443 (HTTPS)
   ▼
Nginx (Docker)
   ├── auth.tudominio.duckdns.org  ──► Authelia:9091 (Docker, red interna)
   ├── web.tudominio.duckdns.org   ──► host:3001  🔒 requiere login
   ├── api.tudominio.duckdns.org   ──► host:3000  🔒 requiere login
   └── docs.tudominio.duckdns.org  ──► host:3002  🔒 requiere login

host = servicios corriendo en el VPS (PM2, Node, etc.)
```

Cada petición a un subdominio protegido pasa por Authelia antes de llegar al servicio. Si no hay sesión activa, redirige al portal de login en `auth.tudominio.duckdns.org`.

---

## Requisitos previos

- VPS con Ubuntu/Debian (o similar con `apt`)
- Cuenta en [DuckDNS](https://www.duckdns.org) con un subdominio creado
- Los puertos **80** y **443** abiertos en el panel del proveedor de VPS
- Docker instalado (o usar `scripts/start.sh` que lo instala)

---

## Instalación en servidor nuevo

### Opción A — Bootstrap completo desde cero

Copia y ejecuta este único comando en el servidor. Instala git, Node.js y Docker, clona el repo y lanza el setup interactivo:

```bash
REPO_URL="git@github.com:TechHoruser/proxy-auth-kit.git" bash <(curl -fsSL https://raw.githubusercontent.com/TechHoruser/proxy-auth-kit/main/scripts/start.sh)
```

O si ya tienes el script en el servidor:

```bash
bash scripts/start.sh
```

El script te pedirá que añadas la deploy key generada a tu repositorio de GitHub antes de clonar.

### Opción B — Si ya tienes el repo clonado

```bash
# 1. Edita la configuración
cp .env.example .env
nano .env          # pon tu DOMAIN y TOKEN de DuckDNS
nano config.yml    # define tus subdominios y puertos

# 2. Instala dependencias y lanza el setup
npm install
npm run setup
```

---

## Configuración

### 1. Variables de entorno — `.env`

Crea tu `.env` copiando el ejemplo:

```bash
cp .env.example .env
```

| Variable | Descripción | Ejemplo |
|---|---|---|
| `DOMAIN` | Tu dominio DuckDNS completo | `miapp.duckdns.org` |
| `TOKEN` | Token de DuckDNS (ver tu cuenta) | `a1b2c3d4-...` |
| `AUTHELIA_JWT_SECRET` | Secreto JWT — se genera automáticamente si está vacío | — |
| `AUTHELIA_SESSION_SECRET` | Secreto de sesión — se genera automáticamente | — |
| `AUTHELIA_STORAGE_ENCRYPTION_KEY` | Clave de cifrado de BD — se genera automáticamente | — |
| `AUTHELIA_TOTP_ISSUER` | Lo sobreescribe el script desde `config.yml` | — |

`DOMAIN` y `TOKEN` son las únicas variables que tienes que rellenar a mano. El resto se genera o se escribe automáticamente.

### 2. Mapeo de subdominios — `config.yml`

```yaml
# El dominio va en .env (DOMAIN=miapp.duckdns.org), no aquí.

authelia:
  totp_issuer: "MiApp"         # nombre en la app de autenticación (Google Auth, etc.)
  default_redirect: "web"      # subdominio al que redirige el dominio raíz

services:
  - subdomain: web
    port: 3001
    protected: true

  - subdomain: api
    port: 3000
    protected: true
    cors_origin: web            # permite peticiones CORS desde web.miapp.duckdns.org

  - subdomain: docs
    port: 3002
    protected: false            # acceso público, solo SSL sin login
```

#### Opciones por servicio

| Campo | Tipo | Descripción |
|---|---|---|
| `subdomain` | string | Nombre del subdominio. Resultado: `nombre.$DOMAIN` |
| `port` | number | Puerto del host al que apunta el proxy |
| `protected` | boolean | `true` = requiere login en Authelia. `false` = solo SSL |
| `cors_origin` | string | (opcional) Subdominio de origen para cabeceras CORS. P.ej: `web` |
| `websocket` | boolean | (opcional) Activa soporte WebSocket (`Upgrade` headers) |
| `public_paths` | string[] | (opcional) Rutas dentro de un servicio protegido que NO requieren auth |

#### Ejemplo con todas las opciones

```yaml
services:
  - subdomain: app
    port: 4000
    protected: true
    cors_origin: web
    websocket: true
    public_paths:
      - /webhook/
      - /health
```

> El subdominio `auth` está reservado para el portal de Authelia y no se puede usar en `services`.

---

## Qué hace `npm run setup`

El script ejecuta estos pasos en orden:

1. **Carga** `config.yml` y `.env`
2. **Genera** los secretos de Authelia si no existen en `.env`
3. **Escribe** `nginx/nginx.conf` dinámicamente a partir de los servicios en `config.yml`
4. **Actualiza** la IP del servidor en DuckDNS
5. **Configura** UFW: abre 22 (SSH), 80 (temporal), 443, y los puertos de tus servicios para la red Docker
6. **Genera** el certificado SSL con Certbot (standalone en puerto 80)
7. **Levanta** los contenedores Docker (`docker compose up -d`)

Si ya habías ejecutado el setup antes, es seguro volver a ejecutarlo: regenera `nginx.conf`, refresca la IP en DuckDNS y reinicia los contenedores.

---

## Gestión de usuarios

```bash
npm run control
```

Menú interactivo con estas opciones:

- **Listar usuarios** — muestra todos los usuarios de Authelia
- **Añadir usuario** — pide nombre, contraseña y email; genera el hash Argon2 automáticamente
- **Cambiar contraseña** — actualiza el hash de un usuario existente
- **Eliminar usuario** — borra un usuario con confirmación
- **Ver código one-time** — muestra el último código de registro MFA del contenedor
- **Logs** — Nginx, Authelia o todos los servicios en vivo
- **Reiniciar servicios** — Docker o renovación forzada de SSL

### Cambiar la contraseña del admin por defecto

El usuario `admin` tiene la contraseña `authelia` por defecto. **Cámbiala antes de exponer el servidor:**

```bash
npm run control
# → Gestionar usuarios → Cambiar contraseña → admin
```

### Añadir un usuario manualmente (sin el panel)

```bash
# Genera el hash
docker run --rm authelia/authelia:latest \
  authelia crypto hash generate argon2 --password 'tucontraseña'

# Añade al final de authelia/users_database.yml:
#   nuevousuario:
#     displayname: "Nombre"
#     password: "$argon2id$..."
#     email: "usuario@ejemplo.com"
#     groups:
#       - users

# Reinicia Authelia
docker compose restart authelia
```

---

## Añadir un nuevo servicio

1. Edita `config.yml` y añade la entrada en `services`
2. Vuelve a ejecutar `npm run setup` — regenera `nginx.conf` y reinicia los contenedores

---

## Renovar certificados SSL

Los certificados de Let's Encrypt duran 90 días. Para renovar:

```bash
npm run control
# → Gestionar servicios → Renovación forzada de SSL
```

O manualmente:

```bash
docker compose stop nginx
docker run --rm \
  -v "$(pwd)/nginx/certs:/etc/letsencrypt" \
  -v "$(pwd)/nginx/certbot-data:/var/lib/letsencrypt" \
  -p 80:80 \
  certbot/certbot renew --standalone --non-interactive
docker compose up -d nginx
```

---

## Estructura del repositorio

```
proxy-auth-kit/
├── config.yml                   # Configuración de dominio y servicios
├── .env                         # Secrets (gitignoreado, créalo desde .env.example)
├── .env.example                 # Plantilla de variables de entorno
├── docker-compose.yml           # Nginx + Authelia
├── authelia/
│   ├── configuration.yml         # Generado por setup.ts a partir de config.yml (gitignoreado)
│   ├── users_database.example.yml # Plantilla del usuario por defecto (admin / authelia)
│   └── users_database.yml         # Usuarios reales (hashes Argon2). Creado desde la plantilla; gitignoreado
├── nginx/
│   └── nginx.conf               # Generado automáticamente por setup.ts (gitignoreado)
├── data/                        # Base de datos Authelia en runtime (gitignoreado)
└── scripts/
    ├── setup.ts                 # Setup inicial y re-despliegue
    ├── control.ts               # Panel de gestión interactivo
    └── start.sh                 # Bootstrap de servidor nuevo (instala Node, Docker, etc.)
```

---

## Tests

```bash
npm install
npm test
```

Cubren la generación de configuración de Nginx y Authelia (YAML válido, reglas
de acceso por servicio/grupo, fallback de `default_redirect`) y toda la API REST
del panel `auth-admin` (alta/edición/borrado de usuarios, grupos y reglas de
acceso por servicio). No requieren Docker.

---

## Solución de problemas

### 502 Bad Gateway

Nginx no llega al servicio del host. Causas habituales:

- El servicio no está corriendo en el puerto configurado
- UFW bloquea la conexión Docker→host. Comprueba:
  ```bash
  ufw status
  ```
  El puerto debe estar permitido desde `172.16.0.0/12`.

### Certbot falla al generar el certificado

- El dominio debe apuntar a la IP del servidor antes de ejecutar el setup
- El puerto 80 debe estar abierto en el panel del proveedor (Contabo, Hetzner, etc.)
- Solo puede haber un proceso escuchando en el puerto 80 durante la generación

### Authelia no arranca

Comprueba los logs:

```bash
docker compose logs authelia
```

Las causas más comunes son un `users_database.yml` malformado o secrets vacíos en `.env`.

### Ver la configuración nginx generada

```bash
cat nginx/nginx.conf
```

O validarla sin reiniciar:

```bash
docker compose exec auth-proxy-nginx nginx -t
```
