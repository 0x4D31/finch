# Finch Example Rules
# See documentation for full matcher options and schema.

# 1. Allow Chrome traffic identified by a specific JA4H
rule "allow-chrome" {
  action = "allow"

  when {
    http_ja4h = ["ge20nn15engb_74941313fa48_000000000000_000000000000"]
  }
}

# 2. Route Safari traffic to example.com
rule "route-safari" {
  action   = "route"
  upstream = "https://example.com/"

  when {
    tls_ja4 = ["t13i2013h2_a09f3c656075_e42f34c56612"]
  }
}

# 3. Tarpit curl‑like requests hitting /yo
rule "tarpit-curl-sus" {
  action         = "deceive"
  deception_mode = "tarpit"

  when all {
    tls_ja3   = ["4f2655722e37c542ebeaf1eed48cbbbb"]
    http_path = ["= /yo"]
  }
}

# 4. Deceive any request that triggers a Suricata HTTP rule
rule "deceive-suri-match" {
  action         = "deceive"
  deception_mode = "galah"

  when {
    suricata_msg = ["~ .+"]   # match if the message is non‑empty
  }
}
