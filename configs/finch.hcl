defaults {
  rule_file = "default.rules.hcl"
  access_log = "../events.jsonl"
  default_action = "deny"
  # upstream_ca_file = "/etc/ssl/private/upstream.pem"
  # upstream_skip_tls_verify = false
}

# enable admin API and SSE feed
admin {
  enabled = true
  addr    = "127.0.0.1:9035"
}

sse {
  enabled = true
  addr    = "127.0.0.1:9036"
}

# example suricata configuration
# suricata {
#   enabled  = true
#   rules_dir = "/etc/suricata/rules"
# }

listener "primary" {
  bind     = "0.0.0.0:8443"
  upstream = "http://localhost:8080"
  tls {}
  access_log = "../logs/public.jsonl"
}

listener "honeypot" {
  bind     = "0.0.0.0:9443"
  upstream = "http://localhost:8081"
  tls {
    # cert = "path/to/cert.pem"
    # key  = "path/to/key.pem"
  }
  access_log = "../logs/honeypot.jsonl"
}
