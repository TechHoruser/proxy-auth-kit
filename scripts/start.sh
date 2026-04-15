#!/usr/bin/env bash

set -euo pipefail

# Bootstrap de servidor nuevo.
# Instala git, Node.js, Docker, genera deploy key, clona el repo y ejecuta el setup.
#
# Uso:
#   REPO_URL="git@github.com:org/proxy-auth-kit.git" bash scripts/start.sh
#
# Variables de entorno opcionales:
#   REPO_URL   — URL SSH del repositorio (se pedirá interactivamente si no se define)
#   REPO_DIR   — directorio de destino para el clone (por defecto: nombre del repo)

REPO_URL="${REPO_URL:-}"
REPO_DIR="${REPO_DIR:-}"

SSH_DIR="${HOME}/.ssh"
AUTHORIZED_KEYS_FILE="${SSH_DIR}/authorized_keys"
DEPLOY_KEY_PATH="${SSH_DIR}/id_ed25519_deploy"
SHELL_PROFILE_FILE="${HOME}/.bashrc"
DEFAULT_REPO_DIR_MARKER="# PROXY_AUTH_KIT_DEFAULT_REPO_DIR"

GITHUB_SSH_COMMAND="ssh -i ${DEPLOY_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

# Añade aquí las claves públicas SSH de los administradores que deben tener acceso al servidor.
# Formato: "ssh-ed25519 AAAA... comentario"
AUTHORIZED_PUBLIC_KEYS=(
	# "ssh-ed25519 AAAA... usuario@maquina"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

print_step() {
	echo
	echo "==> $1"
}

require_sudo() {
	if ! command -v sudo >/dev/null 2>&1; then
		echo "Error: sudo no está disponible."
		exit 1
	fi
}

# ---------------------------------------------------------------------------
# Instalaciones
# ---------------------------------------------------------------------------

install_git() {
	if command -v git >/dev/null 2>&1; then
		echo "git ya está instalado."
		return
	fi

	print_step "Instalando git"
	sudo apt-get update
	sudo apt-get install -y git
}

install_node() {
	if command -v node >/dev/null 2>&1; then
		echo "Node.js ya está instalado ($(node -v))."
		return
	fi

	print_step "Instalando Node.js LTS"
	curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
	sudo apt-get install -y nodejs
	echo "Node.js instalado ($(node -v))."
}

install_docker() {
	if command -v docker >/dev/null 2>&1; then
		echo "Docker ya está instalado ($(docker --version))."
		return
	fi

	print_step "Instalando Docker"
	curl -fsSL https://get.docker.com | sudo sh
	sudo usermod -aG docker "${USER}" || true
	echo "Docker instalado. Puede requerir cerrar sesión y volver a entrar para usarlo sin sudo."
}

# ---------------------------------------------------------------------------
# SSH — authorized_keys
# ---------------------------------------------------------------------------

ensure_ssh_permissions() {
	mkdir -p "${SSH_DIR}"
	chmod 700 "${SSH_DIR}"
	touch "${AUTHORIZED_KEYS_FILE}"
	chmod 600 "${AUTHORIZED_KEYS_FILE}"
}

append_authorized_key() {
	local key="$1"
	if grep -Fqx "${key}" "${AUTHORIZED_KEYS_FILE}"; then
		echo "Clave ya presente: ${key##* }"
	else
		echo "${key}" >> "${AUTHORIZED_KEYS_FILE}"
		echo "Clave añadida: ${key##* }"
	fi
}

ensure_authorized_keys() {
	if [ "${#AUTHORIZED_PUBLIC_KEYS[@]}" -eq 0 ]; then
		echo "ℹ️  No hay claves en AUTHORIZED_PUBLIC_KEYS — se omite configuración de authorized_keys."
		return
	fi

	print_step "Configurando ~/.ssh/authorized_keys"
	ensure_ssh_permissions
	for key in "${AUTHORIZED_PUBLIC_KEYS[@]}"; do
		append_authorized_key "${key}"
	done
}

# ---------------------------------------------------------------------------
# SSH — deploy key para clonar desde GitHub
# ---------------------------------------------------------------------------

ensure_deploy_key() {
	print_step "Generando clave SSH de despliegue"
	if [ -f "${DEPLOY_KEY_PATH}" ] && [ -f "${DEPLOY_KEY_PATH}.pub" ]; then
		echo "Ya existe la clave de despliegue en ${DEPLOY_KEY_PATH}."
		return
	fi

	ssh-keygen -t ed25519 -N "" -f "${DEPLOY_KEY_PATH}" -C "deploy@$(hostname)"
	chmod 600 "${DEPLOY_KEY_PATH}"
	chmod 644 "${DEPLOY_KEY_PATH}.pub"
}

ensure_github_ssh_config() {
	local ssh_config_file
	local marker_start
	local marker_end
	ssh_config_file="${SSH_DIR}/config"
	marker_start="# PROXY_AUTH_KIT_GITHUB_DEPLOY_KEY_START"
	marker_end="# PROXY_AUTH_KIT_GITHUB_DEPLOY_KEY_END"

	print_step "Configurando ~/.ssh/config para la deploy key"
	ensure_ssh_permissions

	if [ ! -f "${DEPLOY_KEY_PATH}" ]; then
		echo "Aviso: no existe ${DEPLOY_KEY_PATH}. Se omite configuración SSH."
		return
	fi

	touch "${ssh_config_file}"
	chmod 600 "${ssh_config_file}"

	sed -i "/^${marker_start}$/,/^${marker_end}$/d" "${ssh_config_file}"

	cat <<EOF >> "${ssh_config_file}"
${marker_start}
Host github.com
  HostName github.com
  User git
  IdentityFile ${DEPLOY_KEY_PATH}
  IdentitiesOnly yes
${marker_end}
EOF

	echo "SSH configurado para github.com usando ${DEPLOY_KEY_PATH}."
}

# ---------------------------------------------------------------------------
# Repo
# ---------------------------------------------------------------------------

derive_deploy_key_url() {
	local repo_url="$1"
	local path_without_git

	if [[ "${repo_url}" =~ ^git@github.com:(.+)\.git$ ]]; then
		path_without_git="${BASH_REMATCH[1]}"
		echo "https://github.com/${path_without_git}/settings/keys"
		return
	fi

	if [[ "${repo_url}" =~ ^https://github.com/(.+)\.git$ ]]; then
		path_without_git="${BASH_REMATCH[1]}"
		echo "https://github.com/${path_without_git}/settings/keys"
		return
	fi

	echo ""
}

infer_repo_dir() {
	local repo_url="$1"
	local dir
	dir="$(basename "${repo_url}")"
	dir="${dir%.git}"
	echo "${dir}"
}

repo_already_exists() {
	if [ -n "${REPO_DIR}" ] && [ -d "${REPO_DIR}" ]; then
		return 0
	fi

	if [ -z "${REPO_DIR}" ] && [ -n "${REPO_URL}" ]; then
		local inferred_dir
		inferred_dir="$(infer_repo_dir "${REPO_URL}")"
		if [ -d "${inferred_dir}" ]; then
			REPO_DIR="${inferred_dir}"
			return 0
		fi
	fi

	return 1
}

prompt_repo_url_if_missing() {
	if [ -n "${REPO_URL}" ]; then
		return
	fi

	echo
	read -r -p "Introduce la URL SSH del repo (ej: git@github.com:org/repo.git): " REPO_URL
	if [ -z "${REPO_URL}" ]; then
		echo "Error: REPO_URL es obligatoria."
		exit 1
	fi
}

clone_repo_with_prompt() {
	local deploy_keys_url
	deploy_keys_url="$(derive_deploy_key_url "${REPO_URL}")"

	print_step "Añadir Deployment Key al repositorio"
	echo "URL del repo: ${REPO_URL}"
	if [ -n "${deploy_keys_url}" ]; then
		echo "Deployment keys: ${deploy_keys_url}"
	fi
	echo
	echo "Clave pública de despliegue de este servidor:"
	cat "${DEPLOY_KEY_PATH}.pub"
	echo
	read -r -p "Añade esta clave en Deployment Keys del repo y pulsa Enter para continuar..."

	if [ -z "${REPO_DIR}" ]; then
		REPO_DIR="$(infer_repo_dir "${REPO_URL}")"
	fi

	if [ -e "${REPO_DIR}" ]; then
		echo "Error: ya existe el path '${REPO_DIR}'. Elimínalo o cambia REPO_DIR."
		exit 1
	fi

	print_step "Verificando autenticación SSH con GitHub"
	if ! ${GITHUB_SSH_COMMAND} -T git@github.com >/tmp/deploy_ssh_check.out 2>&1; then
		if ! grep -Eq "Hi .*! You've successfully authenticated" /tmp/deploy_ssh_check.out; then
			echo "No se pudo autenticar con GitHub. Comprueba la deploy key."
			cat /tmp/deploy_ssh_check.out
			exit 1
		fi
	fi

	print_step "Clonando repositorio"
	if ! GIT_SSH_COMMAND="${GITHUB_SSH_COMMAND}" git clone "${REPO_URL}" "${REPO_DIR}"; then
		echo "Falló el clone. Asegúrate de haber pegado correctamente la clave."
		exit 1
	fi

	echo "Repositorio clonado en: ${REPO_DIR}"
}

run_post_clone_setup() {
	print_step "Instalando dependencias del proyecto"
	(
		cd "${REPO_DIR}"
		npm install
	)

	print_step "Ejecutando setup de despliegue"
	(
		cd "${REPO_DIR}"
		npx tsx scripts/setup.ts
	)
}

configure_ssh_default_repo_dir() {
	local repo_path
	repo_path="$(cd "${REPO_DIR}" && pwd)"

	print_step "Configurando directorio por defecto para sesiones SSH"
	touch "${SHELL_PROFILE_FILE}"

	if grep -Fq "${DEFAULT_REPO_DIR_MARKER}" "${SHELL_PROFILE_FILE}"; then
		sed -i '/^# PROXY_AUTH_KIT_DEFAULT_REPO_DIR$/,/^# END_PROXY_AUTH_KIT_DEFAULT_REPO_DIR$/d' "${SHELL_PROFILE_FILE}"
	fi

	cat <<EOF >> "${SHELL_PROFILE_FILE}"
${DEFAULT_REPO_DIR_MARKER}
if [[ $- == *i* ]] && [ -n "\${SSH_CONNECTION:-}" ] && [ -d "${repo_path}" ]; then
	cd "${repo_path}"
fi
# END_PROXY_AUTH_KIT_DEFAULT_REPO_DIR
EOF

	echo "Las nuevas sesiones SSH abrirán en: ${repo_path}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
	require_sudo

	print_step "Instalación de dependencias base"
	install_git
	install_node
	install_docker

	if repo_already_exists; then
		print_step "Repositorio existente detectado en: ${REPO_DIR}"
		echo "Se omiten generación de clave SSH y clonado."
		ensure_github_ssh_config
		run_post_clone_setup
		configure_ssh_default_repo_dir
		echo
		echo "Bootstrap finalizado correctamente."
		return
	fi

	prompt_repo_url_if_missing

	ensure_authorized_keys
	ensure_deploy_key
	ensure_github_ssh_config
	clone_repo_with_prompt
	run_post_clone_setup
	configure_ssh_default_repo_dir

	echo
	echo "Bootstrap finalizado correctamente."
}

main "$@"
