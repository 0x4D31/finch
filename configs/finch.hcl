defaults {
  # Path to the rule file that will be loaded for all listeners.
  # This path is resolved relative to this configuration file's location.
  rule_file      = "default.rules.hcl"

  # Write access logs to a local events file by default. Modify this to suit your
  # deployment environment.
  access_log     = "../events.jsonl"

  # Specify the fallback action when no rule matches. For an out‑of‑the‑box
  # experience, allow all traffic unless rules dictate otherwise.
  default_action = "allow"
  # upstream_ca_file = "/etc/ssl/private/upstream.pem"
  # upstream_skip_tls_verify = false
}

# Enable the admin API and SSE feed on localhost.
admin {
  enabled = true
  addr    = "127.0.0.1:9035"
}

sse {
  enabled = true
  addr    = "127.0.0.1:9036"
}

# Example listener definitions. Each listener exposes a TLS service on the
# specified bind address and forwards requests to an upstream. Adjust these to
# match your environment.
listener "server1" {
  bind     = "0.0.0.0:8443"
  upstream = "http://localhost:8080"
  tls {}
}

listener "server2" {
  bind     = "0.0.0.0:9443"
  upstream = "http://localhost:8081"
  tls {
    #cert = "path/to/server.crt"
    #key  = "path/to/server.key"
  }
  #access_log = "../logs/primary.jsonl"
}