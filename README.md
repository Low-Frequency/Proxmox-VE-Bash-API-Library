# PVE-authentication-library

This bash library provides a simple workflow for requesting authentication tickets from a proxmox node.

It started as a simple script to authenticate the [bpg/proxmox](https://github.com/bpg/terraform-provider-proxmox) Terraform provider inside a CI/CD pipeline and quickly evolved to a full bash library. The library currently only supports user/password authentication with optional TOTP, but might be expanded with API token support and a simple API wrapper in the future.

The workflow with this library is split into four steps:

1. Initializing configuration
2. Calculating TOTP
3. Authenticating
4. Getting the authentication ticket and CSRF prevention token

Calculating TOTP is only necessary for the initial TOTP setup. If TOTP is already set up, you can pass the TOTP secret via the respective environment variable, or set it in the configuration file and the library will automatically calculate a TOTP token if needed.

## Dependencies

This library depends on the following commands:

| Command | Provided by |
|---------|-------------|
| `curl` | curl |
| `jq` | jq |
| `xxd` | vim-common |
| `base32` | coreutils |
| `openssl` | openssl |

## Configuration

The library is configured via environment variables, or a config file. The following variables can be set:

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| PROXMOX_VE_INSECURE_TLS | Enables insecure communication for self signed certificates | no | 0 |
| PROXMOX_VE_ENDPOINT | The endpoint URL for communication with the Proxmox node. Has to be in the form of [protocol]://[IP\|FQDN]:[port] | yes | |
| PROXMOX_VE_USERNAME | Username for authenticating. Has to be in the form of [username]@[realm] | yes | |
| PROXMOX_VE_PASSWORD | Password for authenticating | yes | |
| PROXMOX_VE_TOTP_SECRET | TOTP secret for MFA calculation | only if TOTP is enabled for the user | |

The library preferes environment variables over the config file, so if you set a config option in both the environment and the file, it will use the environment variable. A mixed configuration is also possible, for example you can configure all secrets as environment variables, but the user and endpoint remain in the config file. Defaults have the least priority and only get set if not otherwise specified.

## Usage

### Loading the library

```bash
source pve_auth.lib.sh
```

### Initialize configuration

```bash
pve_init [OPTIONS] [config_file]
```

Config file is only needed if the environment variables are not set.

`--reinit` option can be used to reload the configuration after changes have been made to either the config file, or environment variables.

### TOTP calculation

Only necessary for initial TOTP setup.

```bash
pve_calc_totp "${PROXMOX_VE_TOTP_SECRET}"
```

### Authentication

```bash
pve_auth
```

### Getting the authentication ticket

```bash
export PROXMOX_VE_AUTH_TICKET=$(pve_get_ticket)
```

### Getting the CSRF prevention token

```bash
export PROXMOX_VE_CSRF_PREVENTION_TOKEN=$(pve_get_csrf_token)
```
