# Proxmox VE Bash API Library

A small, dependency-light Bash library for authenticating against and interacting with the **Proxmox VE API**.

This library provides:

- Configuration handling (config file + environment overrides)
- Authentication via:
  - API tokens
  - Username/password (+ optional TOTP)
- Automatic authentication method selection per API endpoint
- A single, predictable API request interface

It is designed to be **simple, explicit, and safe**, without trying to abstract the Proxmox API itself.

---

## Features

- ✔ Supports **API tokens** and **ticket-based authentication**
- ✔ Automatic fallback: token → ticket (when applicable)
- ✔ Handles **TOTP / 2FA**
- ✔ Minimal auth classification rules (default-to-token policy)
- ✔ Uses `curl --get` for GET query parameters
- ✔ No background state, no daemons, no magic
- ✔ Works with self-signed certificates

---

## Requirements

The following tools must be available in `$PATH`:

- `bash`
- `curl`
- `jq`
- `openssl`
- `base32`
- `xxd`

---

## Installation

Clone or copy the library files somewhere on your system:

```bash
pve-auth.lib.sh
pve-api.lib.sh
```

Then source them in your script:

```bash
source ./pve-api.lib.sh
```

---

## Configuration

Configuration can be provided via:

1. Built-in defaults
2. Default config file: `~/.config/pve-auth.conf`
3. Explicit config file passed to `pve_init`
4. Environment variables (highest priority)

Config file example
```bash
PROXMOX_VE_ENDPOINT="https://pve.example.com:8006"
PROXMOX_VE_USERNAME="root@pam"
PROXMOX_VE_PASSWORD="secret"
PROXMOX_VE_TOTP_SECRET="BASE32SECRET"
PROXMOX_VE_API_TOKEN_ID="root@pam!monitoring"
PROXMOX_VE_API_TOKEN_SECRET="aaaa-bbbb-cccc-dddd"
PROXMOX_VE_INSECURE_TLS=0
```

### Environment variables

| Variable                      | Description                                        |
| ----------------------------- | -------------------------------------------------- |
| `PROXMOX_VE_ENDPOINT`         | Proxmox API endpoint (including protocol and port) |
| `PROXMOX_VE_USERNAME`         | Username (`user@realm`)                            |
| `PROXMOX_VE_PASSWORD`         | Password                                           |
| `PROXMOX_VE_TOTP_SECRET`      | Base32-encoded TOTP secret (optional)              |
| `PROXMOX_VE_API_TOKEN_ID`     | API token ID                                       |
| `PROXMOX_VE_API_TOKEN_SECRET` | API token secret                                   |
| `PROXMOX_VE_INSECURE_TLS`     | Set to `1` to allow self-signed TLS                |

---

## Initialization

Before using the library, initialize it:

```bash
pve_init
```

With an explicit config file:

```bash
pve_init /path/to/config.conf
```

Force reinitialization:

```bash
pve_init --reinit
```

---

## Authentication

Authenticate using available credentials:

```bash
pve_auth
```

Check authentication status:

```bash
pve_auth --status
```

The library automatically determines whether API token authentication, ticket authentication, or no authentication is required for each request.

---

## Making API requests

Basic usage

```bash
pve_api_request \
  --method GET \
  --path nodes
```

The --path value is relative to /api2/json.

---

### GET requests with query parameters

```bash
pve_api_request \
  --method GET \
  --path nodes/pve/lxc \
  --data "type=container"
```

Query parameters are automatically encoded and appended using curl --get.

---

### POST / PUT / DELETE requests

```bash
pve_api_request \
  --method POST \
  --path nodes/pve/lxc \
  --data "vmid=101" \
  --data "ostemplate=local:vztmpl/debian.tar.gz"
```

Use:

`--data` for raw request body

`--data-urlencode` for URL-encoded key/value pairs

---

## Authentication Classification

The library automatically selects the appropriate authentication method per endpoint.

Only a small number of known edge cases are explicitly classified (e.g. login, ticket creation, TFA endpoints).
All other endpoints default to API token authentication, with automatic fallback to ticket auth when needed.

This keeps the ruleset minimal, explicit, and future-proof.

---

## Error Handling

HTTP errors are handled via curl `--fail`

API-level errors are detected via the `.errors` field in responses

Errors are printed to `stderr`

Functions return non-zero exit codes on failure

---

## Disclaimer

This is a hobby project. I won't provide support if you break anything by using this library. Use at your own risk.
