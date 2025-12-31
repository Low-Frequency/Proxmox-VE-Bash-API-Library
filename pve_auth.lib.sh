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
#!      --reinit
#!    pve_auth
#!    pve_get_ticket
#!    pve_get_csrf_token

# Guard against double-sourcing
if [[ -n "${_PROXMOX_AUTH_LIB_LOADED:-}" ]]; then
  return 0
fi

readonly _PROXMOX_AUTH_LIB_LOADED=1

# Default config path
readonly _PVE_DEFAULT_CONFIG_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/pve-auth.conf"

# Dependencies and options
readonly _pve_curl_opts=(--disable --silent --show-error --fail)
readonly _pve_deps=(
  "curl"
  "jq"
  "xxd"
  "base32"
  "openssl"
)

# Internal config
_PVE_INITIALIZED=0
_PVE_ENDPOINT=""
_PVE_USERNAME=""
_PVE_PASSWORD=""
_PVE_TOTP_SECRET=""
_PVE_INSECURE_TLS=0
_PVE_AUTH_TICKET=""
_PVE_CSRF_PREVENTION_TOKEN=""
_PVE_AUTHENTICATED=0

# Color helpers
pve_auth_err() {
  echo -e >&2 "\033[0;31mERROR: $*\033[0m"
}

pve_auth_ok() {
  echo -e "\033[0;32m$*\033[0m"
}

# Check dependencies
pve_chk_dep() {
  for dep in "${_pve_deps[@]}"; do
    if ! command -v "${dep}" >/dev/null; then
      pve_auth_err "Missing dependency: ${dep}"
      return 1
    fi
  done

  return 0
}

# Load config file
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

# Check environment variables
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

  if [[ -n "${PROXMOX_VE_INSECURE_TLS:-}" ]]; then
    _PVE_INSECURE_TLS="${PROXMOX_VE_INSECURE_TLS}"
    case "${_PVE_INSECURE_TLS}" in
      1) ;;
      *) _PVE_INSECURE_TLS=0 ;;
    esac
  fi
}

# Set defaults
pve_set_defaults() {
  : "${_PVE_INSECURE_TLS:=0}"
}

# Initialize config
pve_init() {
  local config_file=""
  local reinit=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --reinit)
        reinit=1
        ;;
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

  # Add possibility to clear configuration and reinitialize afterwards
  if [[ ${reinit} -eq 1 ]]; then
    _PVE_INITIALIZED=0
    _PVE_ENDPOINT=""
    _PVE_USERNAME=""
    _PVE_PASSWORD=""
    _PVE_TOTP_SECRET=""
    _PVE_INSECURE_TLS=0
  fi

  # Prevent unwanted reinitializing
  if [[ ${_PVE_INITIALIZED} -eq 1 ]]; then
    return 0
  fi

  # Reset Authentication and set defaults
  pve_reset_auth
  pve_set_defaults

  # Load default config
  if [[ -f "${_PVE_DEFAULT_CONFIG_FILE}" ]]; then
    pve_load_config_file "${_PVE_DEFAULT_CONFIG_FILE}" || return 1
  fi

  # Load explicit override config
  if [[ -n "${config_file}" ]]; then
    pve_load_config_file "${config_file}" || return 1
  fi

  # Load Environment overrides
  pve_load_env

  # Validation
  if [[ -z "${_PVE_ENDPOINT}" ]]; then
    pve_auth_err "Missing endpoint"
    return 1
  fi

  if [[ -z "${_PVE_USERNAME}" ]]; then
    pve_auth_err "Missing username"
    return 1
  fi

  if [[ -z "${_PVE_PASSWORD}" ]]; then
    pve_auth_err "Missing password"
    return 1
  fi

  _PVE_INITIALIZED=1

  return 0
}

# API error handling function
pve_chk_api_err() {
  local resp="$1"

  if jq -e '.errors != null' >/dev/null <<<"${resp}"; then
    return 1
  fi

  return 0
}

# Calculate TOTP token
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

# Failsafe to reset authentication variables on failure
pve_reset_auth() {
  _PVE_AUTH_TICKET=""
  _PVE_CSRF_PREVENTION_TOKEN=""
  _PVE_AUTHENTICATED=0
}

# Main auth function
pve_auth() {
  local proxmox_api_ticket_path='/api2/json/access/ticket'
  local resp
  local auth_ticket
  local resp_csrf
  local need_tfa
  local totp
  local curl_opts=("${_pve_curl_opts[@]}")

  # Check dependencies
  if ! pve_chk_dep; then
    pve_reset_auth
    return 1
  fi

  # Check for initialization
  if [[ "${_PVE_INITIALIZED:-0}" -eq 0 ]]; then
    pve_auth_err "Library not initialized. Please run 'pve_init' first"
    pve_reset_auth
    return 1
  fi

  # Set insecure TLS
  if [[ "${_PVE_INSECURE_TLS:-0}" -eq 1 ]]; then
    curl_opts+=(--insecure)
  fi

  resp=$(curl "${curl_opts[@]}" \
    --data-urlencode "username=${_PVE_USERNAME}" \
    --data-urlencode "password=${_PVE_PASSWORD}" \
    "${_PVE_ENDPOINT}${proxmox_api_ticket_path}") || {
      pve_reset_auth
      return 1
    }
  
  # Handle Proxmox API errors
  if ! pve_chk_api_err "${resp}"; then
    pve_auth_err "$(jq -r '.errors | to_entries[] | "\(.key): \(.value)"' <<<"${resp}")"
    pve_reset_auth
    return 1
  fi

  # Extract data from API call
  auth_ticket=$(jq -r '.data.ticket' <<<"${resp}")
  resp_csrf=$(jq -r '.data.CSRFPreventionToken' <<<"${resp}")
  need_tfa=$(jq -r '.data.NeedTFA // 0' <<<"${resp}")

  ## Check if the response payload needs a TFA (totp)
  if [[ "$need_tfa" == "1" ]]; then
    if [[ -z "${_PVE_TOTP_SECRET:-}" ]]; then
      pve_auth_err "TOTP required, but no TOTP secret configured"
      pve_reset_auth
      return 1
    else
      totp=$(pve_calc_totp "${_PVE_TOTP_SECRET}")
    fi
  
    # Authenticate with TOTP
    resp=$(curl "${curl_opts[@]}" \
      -H "CSRFPreventionToken: ${resp_csrf}" \
      --data-urlencode "username=${_PVE_USERNAME}" \
      --data-urlencode "tfa-challenge=${auth_ticket}" \
      --data-urlencode "password=totp:${totp}" \
      "${_PVE_ENDPOINT}${proxmox_api_ticket_path}")
  
    # Handle Proxmox API errors (TOTP step)
    if ! pve_chk_api_err "${resp}"; then
      pve_auth_err "$(jq -r '.errors | to_entries[] | "\(.key): \(.value)"' <<<"${resp}")"
      pve_reset_auth
      return 1
    fi
  
    auth_ticket=$(jq -r '.data.ticket' <<<"${resp}")
    resp_csrf=$(jq -r '.data.CSRFPreventionToken' <<<"${resp}")
  fi

  # Export credentials
  if [[ -z "${auth_ticket}" ]]; then
    pve_auth_err "Could not get auth ticket"
    pve_reset_auth
    return 1
  else
    _PVE_AUTH_TICKET="${auth_ticket}"
    pve_auth_ok "Successfully requested auth ticket"
  fi
  
  if [[ -z "${resp_csrf}" ]]; then
    pve_auth_err "Could not get CSRF token"
    pve_reset_auth
    return 1
  else
    _PVE_CSRF_PREVENTION_TOKEN="${resp_csrf}"
    pve_auth_ok "Successfully requested CSRF token"
  fi

  if [[ -z "${_PVE_AUTH_TICKET:-}" ]]; then
    pve_auth_err "Error while getting authentication ticket"
    pve_reset_auth
    return 1
  elif [[ -z "${_PVE_CSRF_PREVENTION_TOKEN:-}" ]]; then
    pve_auth_err "Error while getting CSRF token"
    pve_reset_auth
    return 1
  else
    _PVE_AUTHENTICATED=1
  fi

  return 0
}

pve_get_ticket() {
  if [[ "${_PVE_AUTHENTICATED:-0}" -eq 0 ]]; then
    pve_auth_err "Not authenticated. Please run 'pve_auth' first"
    return 1
  fi

  echo "${_PVE_AUTH_TICKET}"
}

pve_get_csrf_token() {
  if [[ "${_PVE_AUTHENTICATED:-0}" -eq 0 ]]; then
    pve_auth_err "Not authenticated. Please run 'pve_auth' first"
    return 1
  fi

  echo "${_PVE_CSRF_PREVENTION_TOKEN}"
}
