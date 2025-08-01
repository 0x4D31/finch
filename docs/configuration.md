# Configuration File

Finch supports defining multiple listeners and global defaults in a single HCL configuration file. Relative paths in the configuration are resolved relative to the file’s directory. The main configuration, rules and any watched Suricata `.rules` files are reloaded automatically when modified.

## Defaults block

The optional `defaults` block defines values inherited by all listeners:

| Field                      | Description                                                                   |
|---------------------------|--------------------------------------------------------------------------------|
| `rule_file`               | Shared rule file path.  Per‑listener `rule_file` overrides it.                 |
| `access_log`              | Default JSONL log location.                                                    |
| `default_action`          | `allow` or `deny` when no rule matches.                                        |
| `proxy_cache_size`        | Size of the LRU cache of reverse proxies.  Reusing proxies reduces connection. |
| `upstream_ca_file`        | PEM file with additional CAs to trust for upstream HTTPS.                      |
| `upstream_skip_tls_verify`| Skip verification of upstream certificates (use only in trusted environments). |

## Admin and SSE

| Field          | Description                                                                       |
|----------------|-----------------------------------------------------------------------------------|
| `admin.enabled`| Enable the built‑in admin API (default: `true`).                                  |
| `admin.addr`   | Address to listen on for admin endpoints (default: `127.0.0.1:9035`).             |
| `admin.token`  | Bearer token required for admin API requests; can be set via `FINCH_ADMIN_TOKEN`. |
| `sse.enabled`  | Enable the SSE feed (default: `true`).                                            |
| `sse.addr`     | Address for the SSE feed (default: `127.0.0.1:9036`).                             |

## Listener Fields

Each `listener` block defines a single proxy listener:

| Field                       | Description                                                       |
|-----------------------------|-------------------------------------------------------------------|
| `id`                        | Unique name shown in logs.                                        |
| `bind`                      | Address to listen on.                                             |
| `upstream`                  | Default upstream URL for proxying requests.                       |
| `rule_file`                 | Listener‑specific rule file (falls back to `defaults.rule_file`). |
| `access_log`                | Path to write JSONL logs.                                         |
| `tls.cert` / `tls.key`      | Optional certificate and key paths.                               |
| `upstream_ca_file`          | Listener‑specific CA bundle for upstream HTTPS.                   |
| `upstream_skip_tls_verify`  | Skip verification of upstream certificates for this listener.     |

## Suricata and Galah Blocks

If `suricata.enabled = true` and a `rules_dir` is provided, Finch watches the directory for `.rules` files and reloads them automatically. Only supported Suricata keywords will be applied.

The optional `galah` block configures the Galah deception service used by `action = "deceive"` rules. Fields include:

- `provider` – LLM provider (e.g. `openai`).
- `model` – Model name.
- `temperature` – Sampling temperature.
- `api_key` – API key for the provider.
- `config_file` – YAML file containing system and user prompts.
- `cache_file` – Optional cache database.
- `cache_duration` – Cache lifetime in hours.
- `cache_enabled` – Whether to enable caching.
- `event_logging` – Whether to log Galah events.

Download the default Galah [configuration](https://github.com/0x4D31/galah/blob/main/config/config.yaml) from the Galah repository and customise prompts as needed.

## Precedence Rules

1. **Command‑line flags**
2. **Environment variables** (`FINCH_*`)
3. **Main config file**
4. **Built‑in defaults**

Flags and environment variables only override fields in the `defaults` block or top‑level `admin`/`sse` settings when `--config` is used.
