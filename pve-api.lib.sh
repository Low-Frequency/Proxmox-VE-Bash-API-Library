#!/bin/bash

### This library provides functions to request an authentication ticket from a Proxmox node
#!  The library can be configured either through environment variables, or a config file
#!  The following environment variables can be used for configuration:
#!
#!  PROXMOX_VE_ENDPOINT
#!      Endpoint URL to curl for getting the authentication ticket. Has to include the protocol and port
#!
#!  PROXMOX_VE_USERNAME
#!      Username to authenticate with in the form of [user]@[realm]
#!
#!  PROXMOX_VE_PASSWORD
#!      Password for the user
#!
#!  PROXMOX_VE_TOTP_SECRET
#!      Base32 encoded TOTP secret for TOTP calculation if the user has MFA configured
#!      Can be omitted if no MFA is configured
#!
#!  PROXMOX_VE_INSECURE_TLS
#!      Trigger for accepting insecure communication over TLS. Used with self signed certificates
#!
#!
#!  Example config file:
#!
#!  PROXMOX_VE_ENDPOINT="https://pve.example.com"
#!  PROXMOX_VE_USERNAME="root@pam"
#!  PROXMOX_VE_PASSWORD="secret"
#!  PROXMOX_VE_TOTP_SECRET="BASE32SECRET"
#!  PROXMOX_VE_INSECURE_TLS=0
#!
#!  Default config file:
#!    ~/.config/pve-auth.conf
#!    (only loaded if it exists and no explicit config is provided)
#!
#!  Configuration precedence (lowest -> highest):
#!    1. Built-in defaults
#!    2. Default config file (~/.config/pve-auth.conf)
#!    3. Explicit config file (pve_init <file>)
#!    4. Environment variables
#!
#!
#!  Public API:
#!    pve_init [OPTIONS] [config_file]
#!      Initializes the library
#!        --reinit
#!          Forces reinitialization
#!    pve_auth [OPTIONS]
#!      Authenticates the configured user with an API token and/or user/password
#!        --status
#!          Prints an overview of the current authentication status
#!    pve_get_ticket
#!      Prints the currently held authentication ticket
#!    pve_get_csrf_token
#!      Prints the currently held CSRF prevention token
#!    pve_api_request [OPTIONS] [ARGUMENTS]
#!      Makes a request against the Proxmox API
#!        --method
#!          Sets the HTTP method. Possible values:
#!            GET|POST|PUT|DELETE
#!        --path
#!          Defines the API path that is called
#!        --data
#!          Optional raw data for the API call
#!        --data-urlencode
#!          Optional URL-Encoded key/value pairs

### Guard against double-sourcing
if [[ -n "${_PROXMOX_AUTH_LIB_LOADED:-}" ]]; then
  return 0
fi

readonly _PROXMOX_AUTH_LIB_LOADED=1

### Default config path
readonly _PVE_DEFAULT_CONFIG_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/pve-auth.conf"

### Dependencies and options
readonly _pve_curl_opts=(--disable --silent --show-error --fail)
readonly _pve_deps=(
  "curl"
  "jq"
  "xxd"
  "base32"
  "openssl"
)

### Auth modes
readonly PVE_AUTH_NONE="none"
readonly PVE_AUTH_TOKEN="token"
readonly PVE_AUTH_TICKET="ticket"

### Auth classification rules
#!  Format: "METHOD|PATH_PATTERN|AUTH"
readonly _PVE_AUTH_RULES=(
  "GET|access/domains|none"
  "POST|access/openid/auth-url|none"
  "POST|access/openid/login|none"
  "PUT|access/tfa/*/*|ticket"
  "DELETE|access/tfa/*/*|ticket"
  "POST|access/tfa/*|ticket"
  "PUT|access/password|ticket"
  "GET|access/ticket|none"
  "POST|access/ticket|ticket"
  "POST|access/vncticket|ticket"
)

### Internal config
_PVE_INITIALIZED=0
_PVE_ENDPOINT=""
_PVE_USERNAME=""
_PVE_PASSWORD=""
_PVE_TOTP_SECRET=""
_PVE_API_TOKEN_ID=""
_PVE_API_TOKEN_SECRET=""
_PVE_INSECURE_TLS=0
_PVE_AUTH_TICKET=""
_PVE_CSRF_PREVENTION_TOKEN=""
_PVE_AUTH_HAS_TICKET=0
_PVE_AUTH_HAS_TOKEN=0
_PVE_HAS_AUTH=0

### Color helpers
#!  Formats success and error messages
pve_auth_err() {
  echo -e >&2 "\033[0;31mERROR: $*\033[0m"
}

pve_auth_ok() {
  echo -e "\033[0;32m$*\033[0m"
}

pve_auth_warn() {
  echo -e "\033[0;33m$*\033[0m"
}

### Check dependencies
#!  Loops over all dependencies and checks if the requirements are met
pve_chk_dep() {
  for dep in "${_pve_deps[@]}"; do
    if ! command -v "${dep}" >/dev/null; then
      pve_auth_err "Missing dependency: ${dep}"
      return 1
    fi
  done

  return 0
}

### Load config file
#!  Loads the config from a given file
pve_load_config_file() {
  local file="$1"

  if [[ -z "${file}" ]]; then
    return 0
  fi

  if ! [[ -f "${file}" ]]; then
    pve_auth_err "Config file not found: ${file}"
    return 1
  fi

  source "${file}"
}

### Check environment variables
#!  Loads all available environement variables
pve_load_env() {
  if [[ -n "${PROXMOX_VE_ENDPOINT:-}" ]]; then
    _PVE_ENDPOINT="${PROXMOX_VE_ENDPOINT%/}"
  fi

  if [[ -n "${PROXMOX_VE_USERNAME:-}" ]]; then
    _PVE_USERNAME="${PROXMOX_VE_USERNAME}"
  fi

  if [[ -n "${PROXMOX_VE_PASSWORD:-}" ]]; then
    _PVE_PASSWORD="${PROXMOX_VE_PASSWORD}"
  fi

  if [[ -n "${PROXMOX_VE_TOTP_SECRET:-}" ]]; then
    _PVE_TOTP_SECRET="${PROXMOX_VE_TOTP_SECRET}"
  fi

  if [[ -n "${PROXMOX_VE_API_TOKEN_ID:-}" ]]; then
    _PVE_API_TOKEN_ID="${PROXMOX_VE_API_TOKEN_ID}"
  fi

  if [[ -n "${PROXMOX_VE_API_TOKEN_SECRET:-}" ]]; then
    _PVE_API_TOKEN_SECRET="${PROXMOX_VE_API_TOKEN_SECRET}"
  fi

  if [[ -n "${PROXMOX_VE_INSECURE_TLS:-}" ]]; then
    _PVE_INSECURE_TLS="${PROXMOX_VE_INSECURE_TLS}"
    case "${_PVE_INSECURE_TLS}" in
      1) ;;
      *) _PVE_INSECURE_TLS=0 ;;
    esac
  fi
}

### Set defaults
pve_set_defaults() {
  : "${_PVE_INSECURE_TLS:=0}"
}

### Initialize config
#!  Initializes the library. Calls all the configuration loading functions in the correct order
pve_init() {
  local config_file=""
  local reinit=0

  ### Check dependencies
  if ! pve_chk_dep; then
    return 1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --reinit) reinit=1 ;;
      -*)
        pve_auth_err "Unknown option: ${1}"
        return 1
        ;;
      *)
        if [[ -n "${config_file}" ]]; then
          pve_auth_err "Multiple config files specified"
          return 1
        fi
        config_file="${1}"
        ;;
    esac
    shift
  done

  ### Add possibility to clear configuration and reinitialize afterwards
  if [[ ${reinit} -eq 1 ]]; then
    _PVE_INITIALIZED=0
    _PVE_ENDPOINT=""
    _PVE_USERNAME=""
    _PVE_PASSWORD=""
    _PVE_TOTP_SECRET=""
    _PVE_INSECURE_TLS=0
    _PVE_API_TOKEN_ID=""
    _PVE_API_TOKEN_SECRET=""
  fi

  ### Prevent unwanted reinitializing
  if [[ ${_PVE_INITIALIZED} -eq 1 ]]; then
    return 0
  fi

  ### Reset Authentication and set defaults
  pve_reset_auth
  pve_set_defaults

  ### Load default config
  if [[ -f "${_PVE_DEFAULT_CONFIG_FILE}" ]]; then
    pve_load_config_file "${_PVE_DEFAULT_CONFIG_FILE}" || return 1
  fi

  ### Load explicit override config
  if [[ -n "${config_file}" ]]; then
    pve_load_config_file "${config_file}" || return 1
  fi

  ### Load Environment overrides
  pve_load_env

  ### Validation
  if [[ -z "${_PVE_ENDPOINT}" ]]; then
    pve_auth_err "Missing endpoint"
    return 1
  fi

  if [[ -z "${_PVE_USERNAME}" || -z "${_PVE_PASSWORD}" ]] && [[ -z "${_PVE_API_TOKEN_ID}" || -z "${_PVE_API_TOKEN_SECRET}" ]]; then
    pve_auth_err "Neither ticket nor API token credentials provided"
    return 1
  fi

  _PVE_INITIALIZED=1

  return 0
}

### API error handling function
#!  Checks an API response for errors
pve_chk_api_err() {
  local resp="$1"

  if jq -e '.errors != null' >/dev/null <<<"${resp}"; then
    return 1
  fi

  return 0
}

### Calculate TOTP token
#!  Calculates the TOTP token based on a passed secret
pve_calc_totp() {
  local totp_secret="$1"
  local count
  local hexkey
  local hash
  local extracted
  local offset

  count="$(printf '%.16x' $(($(date +%s)/30)))"
  hexkey="$(echo -n "${totp_secret}" | base32 -d | xxd -p)"
  hash="$(
    echo -n "${count}" |
    xxd -r -p |
    openssl dgst -sha1 -mac HMAC -macopt hexkey:"${hexkey}" |
    awk '{print $NF}'
  )"
  offset="$((16#${hash:39}))"
  extracted="${hash:$((offset * 2)):8}"

  printf '%06d\n' "$(((16#$extracted & 16#7fffffff) % 1000000))"
}

### Failsafe to reset authentication variables on failure
pve_reset_auth() {
  _PVE_AUTH_TICKET=""
  _PVE_CSRF_PREVENTION_TOKEN=""
  _PVE_HAS_AUTH=0
  _PVE_AUTH_HAS_TICKET=0
  _PVE_AUTH_HAS_TOKEN=0
}

### Print authentication status
pve_print_auth_status() {
  if [[ "${_PVE_INITIALIZED:-0}" -eq 0 ]]; then
    pve_auth_err "Library not initialized. Please run 'pve_init' first"
    return 1
  fi

  echo -e "### Authentication status ###"
  
  ### Ticket
  echo -n "Ticket authentication:    "
  if [[ "${_PVE_AUTH_HAS_TICKET}" -eq 1 ]]; then
    pve_auth_ok "Authenticated"
  elif [[ "${_PVE_AUTH_HAS_TOKEN}" -eq 1 ]]; then
    pve_auth_warn "Not authenticated"
  else
    pve_auth_err "Not authenticated"
  fi

  ### Token
  echo -n "API token authentication: "
  if [[ "${_PVE_AUTH_HAS_TOKEN}" -eq 1 ]]; then
    pve_auth_ok "Authenticated"
  elif [[ "${_PVE_AUTH_HAS_TICKET}" -eq 1 ]]; then
    pve_auth_warn "Not authenticated"
  else
    pve_auth_err "Not authenticated"
  fi

  return 0
}

### Main auth function
#!  Tries token and user/password authentication
pve_auth() {
  local print_status=0
  local has_auth=0
  local verbose=""

  ### Print out status
  while [[ $# -gt 0 ]]; do
    case "${1}" in
      --status) print_status=1 ;;
      --verbose) verbose="--verbose" ;;
      *)
        pve_auth_err "Unknown option for pve_auth: ${1}"
        return 1
        ;;
    esac
    shift
  done

  if [[ "${print_status}" -eq 1 ]]; then
    if ! pve_print_auth_status; then
      return 1
    fi
    return 0
  fi

  ### Check for initialization
  if [[ "${_PVE_INITIALIZED:-0}" -eq 0 ]]; then
    pve_auth_err "Library not initialized. Please run 'pve_init' first"
    pve_reset_auth
    return 1
  fi
  
  ### Set token authentication status
  if [[ -n "${_PVE_API_TOKEN_ID}" && -n "${_PVE_API_TOKEN_SECRET}" ]]; then
    _PVE_AUTH_HAS_TOKEN=1
    has_auth=1
  else
    _PVE_AUTH_HAS_TOKEN=0
  fi

  ### Set username/password authentication status
  if [[ -n "${_PVE_USERNAME:-}" && -n "${_PVE_PASSWORD:-}" ]]; then
    if pve_auth_ticket "${verbose}"; then
      _PVE_AUTH_HAS_TICKET=1
      has_auth=1
    else
      _PVE_AUTH_HAS_TICKET=0
    fi
  else
    _PVE_AUTH_HAS_TICKET=0
  fi

  ### Check if any authentication method is available
  if [[ "${has_auth}" -ne 1 ]]; then
    pve_reset_auth
    pve_auth_err "No usable authentication method available"
    return 1
  else
    _PVE_HAS_AUTH=1
  fi
  
  return 0
}

### Ticket authentication
#!  Authenticates the user via username and password
pve_auth_ticket() {
  local verbose=""
  local proxmox_api_ticket_path='/api2/json/access/ticket'
  local resp
  local auth_ticket
  local resp_csrf
  local need_tfa
  local totp
  local curl_opts=("${_pve_curl_opts[@]}")

  ### Parse arguments
  while [[ $# -gt 0 ]]; do
    case "${1}" in
      --verbose) verbose="--verbose" ;;
      *)
        pve_auth_err "Unknown argument for pve_auth_ticket: ${1}"
        return 1
        ;;
    esac
    shift
  done

  ### Set insecure TLS
  if [[ "${_PVE_INSECURE_TLS:-0}" -eq 1 ]]; then
    curl_opts+=(--insecure)
  fi

  resp=$(curl "${curl_opts[@]}" \
    --data-urlencode "username=${_PVE_USERNAME}" \
    --data-urlencode "password=${_PVE_PASSWORD}" \
    "${_PVE_ENDPOINT}${proxmox_api_ticket_path}") || {
      return 1
    }

  ### Extract data from API call
  auth_ticket=$(jq -r '.data.ticket' <<<"${resp}")
  resp_csrf=$(jq -r '.data.CSRFPreventionToken' <<<"${resp}")
  need_tfa=$(jq -r '.data.NeedTFA // 0' <<<"${resp}")

  ### Check if the response payload needs a TFA (totp)
  if [[ "$need_tfa" == "1" ]]; then
    if [[ -z "${_PVE_TOTP_SECRET:-}" ]]; then
      pve_auth_err "TOTP required, but no TOTP secret configured"
      return 1
    else
      totp=$(pve_calc_totp "${_PVE_TOTP_SECRET}")
    fi

    ### Authenticate with TOTP
    resp=$(curl "${curl_opts[@]}" \
      -H "CSRFPreventionToken: ${resp_csrf}" \
      --data-urlencode "username=${_PVE_USERNAME}" \
      --data-urlencode "tfa-challenge=${auth_ticket}" \
      --data-urlencode "password=totp:${totp}" \
      "${_PVE_ENDPOINT}${proxmox_api_ticket_path}")
  fi

  ### Update internal auth state
  if ! pve_set_auth_ticket "${resp}" "${verbose}"; then
    return 1
  fi

  return 0
}

### Gets the authentication ticket if available
pve_get_ticket() {
  if [[ "${_PVE_AUTH_HAS_TICKET:-0}" -eq 0 ]]; then
    pve_auth_err "Ticket authentication not available"
    return 1
  fi

  echo "${_PVE_AUTH_TICKET}"
}

### Gets the CSRF prevention token if available
pve_get_csrf_token() {
  if [[ "${_PVE_AUTH_HAS_TICKET:-0}" -eq 0 ]]; then
    pve_auth_err "Ticket authentication not available"
    return 1
  fi

  echo "${_PVE_CSRF_PREVENTION_TOKEN}"
}

### Sets internal authentication status
pve_set_auth_ticket() {
  local verbose=0
  local resp="${1:-}"
  local auth_ticket
  local resp_csrf

  shift || true

  ### Parse arguments
  while [[ $# -gt 0 ]]; do
    case "${1}" in
      --verbose) verbose=1 ;;
      *)
        pve_auth_err "Unknown argument for pve_set_auth_ticket: ${1}"
        return 1
        ;;
    esac
    shift
  done

  ### Ensure no API-level errors
  if ! pve_chk_api_err "${resp}"; then
    pve_auth_err "$(jq -r '.errors | to_entries[] | "\(.key): \(.value)"' <<<"${resp}")"
    return 1
  fi

  ### Extract ticket and csrf data from response
  auth_ticket=$(jq -er '.data.ticket' <<<"${resp}") || {
    return 1
  }

  resp_csrf=$(jq -er '.data.CSRFPreventionToken' <<<"${resp}") || {
    return 1
  }

  ### Handle auth ticket
  if [[ -z "${auth_ticket}" ]]; then
    pve_auth_err "Could not get auth ticket"
    return 1
  else
    _PVE_AUTH_TICKET="${auth_ticket}"
    if [[ "${verbose}" -eq 1 ]]; then
      pve_auth_ok "Successfully requested auth ticket"
    fi
  fi

  ### Handle CSRF prevention token
  if [[ -z "${resp_csrf}" ]]; then
    pve_auth_err "Could not get CSRF token"
    return 1
  else
    _PVE_CSRF_PREVENTION_TOKEN="${resp_csrf}"
    if [[ "${verbose}" -eq 1 ]]; then
      pve_auth_ok "Successfully requested CSRF token"
    fi
  fi

  ### Check authentication status
  if [[ -z "${_PVE_AUTH_TICKET:-}" ]]; then
    pve_auth_err "Error while getting authentication ticket"
    return 1
  elif [[ -z "${_PVE_CSRF_PREVENTION_TOKEN:-}" ]]; then
    pve_auth_err "Error while getting CSRF token"
    return 1
  fi

  return 0
}

### Helper for argument parsing
#!  Checks if the given argument has a value that doesn't start with a dash (next argument)
pve_require_value() {
  local opt="$1"
  local val="${2}"

  if [[ -z "${val}" || "${val}" == -* ]]; then
    pve_auth_err "Missing or invalid value for ${opt}"
    return 1
  fi

  return 0
}

### Classify authentication method for an API request
#!  Usage: pve_classify_auth <METHOD> <API_PATH>
#!  Output: none | token | ticket
pve_classify_auth() {
  local method="${1^^}"
  local path="$2"
  local rule
  local r_method
  local r_path
  local r_auth

  ### Trim leading and trailing / from path for safety
  path="${path%/}"
  path="${path#/}"

  if [[ -z "${method}" || -z "${path}" ]]; then
    pve_auth_err "pve_classify_auth: missing method or path"
    return 1
  fi

  for rule in "${_PVE_AUTH_RULES[@]}"; do
    IFS='|' read -r r_method r_path r_auth <<<"${rule}"

    if [[ "${r_method}" != "*" && "${r_method}" != "${method}" ]]; then
      continue
    fi

    if [[ ! "${path}" == ${r_path} ]]; then
      continue
    fi

    echo "${r_auth}"
    return 0
  done

  ### Default policy: token preferred
  echo "${PVE_AUTH_TOKEN}"
  return 0
}

### Resolve classified auth method to a usable one
#!  Usage: pve_resolve_auth <classified_auth>
#!  Output: none | token | ticket
pve_resolve_auth() {
  local auth="$1"

  case "${auth}" in
    none)
      echo "none"
      return 0
      ;;
    token)
      if [[ "${_PVE_AUTH_HAS_TOKEN}" -eq 1 ]]; then
        echo "token"
        return 0
      elif [[ "${_PVE_AUTH_HAS_TICKET}" -eq 1 ]]; then
        echo "ticket"
        return 0
      fi
      ;;
    ticket)
      if [[ "${_PVE_AUTH_HAS_TICKET}" -eq 1 ]]; then
        echo "ticket"
        return 0
      fi
      ;;
    *)
      pve_auth_err "Unknown authentication method: ${auth}"
      return 1
      ;;
  esac

  pve_auth_err "No usable authentication method available (${auth})"
  return 1
}

### Header builder for API requests
pve_build_header(){
  local method="${1:-}"
  local auth="${2:-}"
  local header=()

  case "${method}" in
    GET|PUT|POST|DELETE) ;;
    *)
      pve_auth_err "Unsupported method for API call: ${method}"
      return 1
      ;;
  esac

  if [[ -z "${auth}" ]]; then
    pve_auth_err "No authentication method specified"
    return 1
  fi

  case "${auth}" in
    token)
      header+=(
        -X "${method}"
        -H "Authorization: PVEAPIToken=${_PVE_API_TOKEN_ID}=${_PVE_API_TOKEN_SECRET}"
      )
      ;;
    ticket)
      header+=(
        -X "${method}"
        -H "Cookie: PVEAuthCookie=$(pve_get_ticket)"
      )
      if [[ "${method}" != "GET" ]]; then
        header+=(-H "CSRFPreventionToken: $(pve_get_csrf_token)")
      fi
      ;;
    none) header+=(-X "${method}") ;;
    *)
      pve_auth_err "Unknown auth method: ${auth}"
      return 1
      ;;
  esac

  printf '%s\n' "${header[@]}"
}

### Default API request function
#!  Unifies the API calls into a predictable format
pve_api_request() {
  local method="GET"
  local path=""
  local data_args=()
  local curl_opts=("${_pve_curl_opts[@]}")
  local resp=""
  local auth
  local headers

  ### Parsing arguments
  while [[ $# -gt 0 ]]; do
    case "${1}" in
      --method)
        if pve_require_value "${1}" "${2}"; then
          method="${2^^}"
        else
          return 1
        fi
        ;;
      --path)
        if pve_require_value "${1}" "${2}"; then
          path="${2#api2/json/}"
        else
          return 1
        fi
        ;;
      --data-urlencode)
        if pve_require_value "${1}" "${2}"; then
          data_args+=(--data-urlencode "${2}")
        else
          return 1
        fi
        ;;
      --data)
        if pve_require_value "${1}" "${2}"; then
          data_args+=(--data "${2}")
        else
          return 1
        fi
        ;;
      *)
        pve_auth_err "Unknown option: ${1}"
        return 1
        ;;
    esac
    shift 2
  done

  if [[ -z "${path}" ]]; then
    pve_auth_err "API path not specified"
    return 1
  fi

  ### Allowing insecure TLS communication for self signed certificates
  if [[ "${_PVE_INSECURE_TLS:-0}" -eq 1 ]]; then
    curl_opts+=(--insecure)
  fi

  ### Resolving necessary authentication method
  auth=$(pve_classify_auth "${method}" "${path}") || return 1
  auth=$(pve_resolve_auth "${auth}") || return 1

  ### Checking for authentication
  if [[ "${auth}" != "none" && "${_PVE_HAS_AUTH:-0}" -ne 1 ]]; then
    pve_auth_err "Not authenticated"
    return 1
  fi

  ### Building headers and method for API call
  mapfile -t headers < <(pve_build_header "${method}" "${auth}") || return 1
  curl_opts+=("${headers[@]}")

  ### Checking required variables for API call
  case "${method}" in
    GET)
      if [[ "${#data_args[@]}" -gt 0 ]]; then
        curl_opts+=(--get)
        curl_opts+=("${data_args[@]}")
      fi
      ;;
    POST|PUT|DELETE)
      ### Adding data to API call
      if [[ "${#data_args[@]}" -gt 0 ]]; then
        curl_opts+=("${data_args[@]}")
      fi
      ;;
    *)
      pve_auth_err "Invalid HTTP method: ${method}"
      return 1
      ;;
  esac

  ### API call
  resp=$(curl "${curl_opts[@]}" "${_PVE_ENDPOINT}/api2/json/${path}") || {
    pve_auth_err "API call failed"
    return 1
  }

  ### Check for errors in response
  if ! pve_chk_api_err "${resp}"; then
    pve_auth_err "$(jq -r '.errors | to_entries[] | "\(.key): \(.value)"' <<<"${resp}")"
    return 1
  fi

  ### Return API response
  echo "${resp}"
}
