# Rule Specification

Finch rules are written in HCL. Each rule defines an `action` (`allow`, `deny`, `route` or `deceive`) and optional metadata such as an `upstream` URL, `strip_prefix`, `expires` timestamp or `deception_mode`. Conditions are grouped under a single `when` block; additional nested `when` blocks may be added for complex logic. If no label is specified the default aggregator is `all` (logical AND). A rule with multiple top‑level `when` blocks is invalid.

## Condition fields

- `tls_ja3`, `tls_ja4` – TLS fingerprints
- `http_ja4h` – JA4H HTTP request fingerprint
- `http_http2` – Akamai HTTP/2 fingerprint string
- `http_method` – HTTP method values (e.g. `GET`, `POST`)
- `http_path` – request path (matching prefix, exact or regex)
- `http_header` – map of header names to value patterns. Keys are case-insensitive and must be quoted. Prefix values with `i:` for case-insensitive comparison.
- `client_ip` – source IP or CIDR range
- `suricata_msg` – matched Suricata rule messages

String values support operators to control the match type:

  - `= value` for exact match (default if no operator)
  - `^ prefix` for prefix match
  - `~ regex` for regular expressions

Values may be single strings or lists. When a list is used, any value that matches satisfies the condition. The outer `when` block’s `all`/`any` label controls how different fields are combined

When the upstream URL ends with `/`, Finch strips the matching prefix from the request path before proxying. Alternatively, set `strip_prefix` explicitly to override the default behaviour.

## Examples

```hcl
# Deny malicious fingerprints
rule "deny-malicious" {
  action = "deny"

  when all {
    tls_ja4   = ["abcd1234efgh5678"]
    http_ja4h = ["^ badfinger"]
    client_ip = ["203.0.113.0/24"]
  }
}

# Send suspicious traffic to a honeypot
rule "sandbox" {
  action   = "route"
  upstream = "http://hp.internal/"

  when any {
    suricata_msg = ["^ Exploit"]
    http_path    = ["^ /secret/"]
  }
}

# Deny requests with bad headers
rule "deny-header" {
  action = "deny"

  when {
    http_header = {
      "X-Test" = ["bad"]
    }
  }
}

# Route API requests to v2
rule "api-v2" {
  action   = "route"
  upstream = "https://api.example.com/v2/"

  when all {
    http_path   = ["^ /api/"]
    http_method = ["GET", "POST"]
  }
}

# Route static assets and strip /assets/
rule "static" {
  action       = "route"
  upstream     = "https://backend.local/static/"
  strip_prefix = "/assets/"

  when {
    http_path = ["^ /assets/"]
  }
}
```

## Deception Mode

The `deceive` action instructs Finch to generate a fake HTTP response instead of forwarding the request. The response is produced by an external deception service and controlled via the optional `deception_mode` attribute. Supported modes:

1. `galah` – Use [Galah](https://github.com/0x4D31/galah) to generate LLM-based responses. This is the default mode when `deception_mode` is omitted. A `galah` block must be present in the configuration; otherwise Finch exits with an error.
2. `tarpit` – Send a trickle of random bytes for 45–120 seconds (configurable) to frustrate scanners. Concurrent responses are limited (16 by default).
3. `agent` *(upcoming)* – Serve static responses crafted ahead of time by a local AI agent. For unknown paths the agent returns a stub response and later learns a realistic one.


Example using Galah:

```hcl
rule "honeypot" {
  action         = "deceive"
  deception_mode = "galah"

  when {
    http_path = ["/admin"]
  }
}
```

Refer to the Galah documentation for configuration options.