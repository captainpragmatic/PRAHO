# shellcheck shell=bash
# =============================================================================
# PRAHO - Compose helper for the standalone deployment scripts
# =============================================================================
# Sourced by deploy.sh, rollback.sh and restore.sh, after they set PROJECT_ROOT and DEPLOY_DIR.
#
# The compose files live in deploy/, so a bare `docker compose -f deploy/...` reads deploy/.env,
# which no documented step creates, and every ${VAR:?} fails. praho_compose passes the operator's
# env file instead: --env-file for interpolation, and PRAHO_ENV_FILE for the platform's env_file.
# The file is never sourced by the shell; single values are read with praho_env_value.
#
# Runs under macOS's bash 3.2 too: no associative arrays, and empty arrays expand as
# ${a[@]+"${a[@]}"} under `set -u`.

PRAHO_ENV_NAME="prod"
PRAHO_ENV_PATH=""
PRAHO_ARGS=()

praho_die() {
    echo -e "\033[0;31m[ERROR]\033[0m $1" >&2
    exit 1
}

# Take --env NAME and --env-file PATH out of the arguments; the rest are left in PRAHO_ARGS.
praho_parse_env_args() {
    PRAHO_ARGS=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --env)
                [[ $# -ge 2 ]] || praho_die "--env needs a value: prod or staging"
                PRAHO_ENV_NAME="$2"
                shift 2
                ;;
            --env-file)
                [[ $# -ge 2 ]] || praho_die "--env-file needs a path"
                PRAHO_ENV_PATH="$2"
                shift 2
                ;;
            *)
                PRAHO_ARGS+=("$1")
                shift
                ;;
        esac
    done
}

# Print KEY's value as Compose reads it (the last declaration wins): KEY=value, KEY="value",
# KEY='value', and an unquoted value's trailing " # comment". Prints nothing when KEY is absent.
praho_env_value() {
    awk -v key="$1" '
        index($0, key "=") == 1 { value = substr($0, length(key) + 2); found = 1 }
        END {
            if (!found) exit
            first = substr(value, 1, 1)
            if (first == "\"" || first == "\047") {
                rest = substr(value, 2)
                end = index(rest, first)
                value = (end > 0) ? substr(rest, 1, end - 1) : rest
            } else {
                sub(/[ \t]+#.*$/, "", value)
                sub(/[ \t]+$/, "", value)
            }
            print value
        }' "$PRAHO_ENV_FILE"
}

# Resolve the env file from --env/--env-file, refuse the development file and a settings module
# the images do not run, then export PRAHO_ENV_FILE as an absolute path.
praho_load_env() {
    local path settings expected=""
    if [[ -n "$PRAHO_ENV_PATH" ]]; then
        path="$PRAHO_ENV_PATH"
    else
        case "$PRAHO_ENV_NAME" in
            prod) expected="config.settings.prod" ;;
            staging) expected="config.settings.staging" ;;
            *) praho_die "--env must be prod or staging, not '${PRAHO_ENV_NAME}'" ;;
        esac
        path="${PROJECT_ROOT}/.env.${PRAHO_ENV_NAME}"
        [[ -f "$path" ]] || praho_die "${path} not found. Create it with: cp .env.example.${PRAHO_ENV_NAME} .env.${PRAHO_ENV_NAME}"
    fi
    [[ -f "$path" ]] || praho_die "Env file not found: ${path}"
    path="$(realpath "$path")"

    # The repo-root .env is the development file `make dev` reads (DEBUG on, dev settings).
    if [[ -e "${PROJECT_ROOT}/.env" && "$path" == "$(realpath "${PROJECT_ROOT}/.env")" ]]; then
        praho_die "Refusing ${PROJECT_ROOT}/.env: it is the development env file. Use .env.prod or .env.staging."
    fi

    export PRAHO_ENV_FILE="$path"
    settings="$(praho_env_value DJANGO_SETTINGS_MODULE)"
    settings="${settings:-config.settings.prod}"  # the compose files' own default
    case "$settings" in
        config.settings.prod | config.settings.staging) ;;
        *) praho_die "DJANGO_SETTINGS_MODULE=${settings} in ${path}: the images run config.settings.prod or config.settings.staging" ;;
    esac
    if [[ -n "$expected" && "$settings" != "$expected" ]]; then
        praho_die "--env ${PRAHO_ENV_NAME} but ${path} selects ${settings}. Set DJANGO_SETTINGS_MODULE=${expected}."
    fi
    PRAHO_SETTINGS_MODULE="$settings"
    # A shell variable beats the env file in Compose interpolation; the file's value was checked above.
    unset DJANGO_SETTINGS_MODULE
}

# Production settings refuse to import without these keys. The compose files only default them
# to empty (staging runs without them), so a production deploy checks them here, before Compose.
praho_require_production_keys() {
    local key missing=""
    [[ "$PRAHO_SETTINGS_MODULE" == "config.settings.prod" ]] || return 0
    for key in DJANGO_ENCRYPTION_KEY CREDENTIAL_VAULT_MASTER_KEY; do
        [[ -n "$(praho_env_value "$key")" ]] || missing="${missing} ${key}"
    done
    [[ -z "$missing" ]] || praho_die "Production settings need${missing} in ${PRAHO_ENV_FILE}"
}

# praho_compose TYPE [--profile NAME ...] COMMAND [ARGS...]
praho_compose() {
    local type="$1"
    shift
    docker compose --env-file "$PRAHO_ENV_FILE" -f "${DEPLOY_DIR}/docker-compose.${type}.yml" "$@"
}
