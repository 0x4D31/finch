# Finch rule examples
#
# This file contains sample rules demonstrating each supported action. Copy
# individual rules into your own rules file and tailor the matching conditions
# to your environment. Refer to the rule schema documentation for further
# details.
#
# Note: The `deceive` action depends on a Galah configuration. Finch will exit
# with an error if a deceive rule is loaded without a corresponding `galah`
# block in your configuration.

# ---------------------------------------------------------------------------
# 1. Allow traffic matching a JA4H fingerprint (e.g. a specific Chrome build).
#    Requests matching this rule bypass any downstream filters.
rule "allow-chrome" {
  action = "allow"

  when {
    http_ja4h = ["ge20nn15engb_74941313fa48_000000000000_000000000000"]
  }
}

# ---------------------------------------------------------------------------
# 2. Route Safari traffic to a different upstream based on its TLS fingerprint.
rule "route-safari" {
  action   = "route"
  upstream = "https://example.com/"

  when {
    tls_ja4 = ["t13i2013h2_a09f3c656075_e42f34c56612"]
  }
}

# ---------------------------------------------------------------------------
# 3. Deceive requests to admin paths or those that trigger a Suricata HTTP rule.
#    Requires a configured Galah deception service.
rule "deceive-admin" {
  action = "deceive"

  when any {
    http_path = ["^ /admin"]
    suricata_msg = ["~ .+"]
  }
}

# ---------------------------------------------------------------------------
# 4. Deny rules: block common scanning tools by their JA3/JA4 fingerprints.

# Block Nmap TLS fingerprints (no‑SNI and SNI variants)
rule "block-nmap" {
  action = "deny"

  when all {
    tls_ja3 = [
      "ee2b1d84fa1d67ced85c6284a724888e",
      # no-SNI probe
      "2fd66e5dee273eef288bf5efcc10a71a",
    ]

    tls_ja4 = [
      "t13d801100_59a17bb9eabe_d41ae481755e",
      # no-SNI probe
      "t13i801000_59a17bb9eabe_d41ae481755e",
    ]
  }
}

# Block ZAP active‑scan traffic
rule "block-zap" {
  action = "deny"

  when all {
    # TLS fingerprints
    tls_ja3   = [
      "795a08fe385896aee616d3b7236502da",
      "20ee858fb3bcdda802d5f5caaa5e1122",
    ]
    tls_ja4   = [
      "t13i371100_db35923f8641_7c76daad20ec",
      "t13i371200_db35923f8641_867a32efce91"
    ]

    # HTTP fingerprint
    http_ja4h = ["ge11nn040000_d5cb08ea9ac8_000000000000_000000000000"]
  }
}

# Block Burp Repeater
rule "block-burp" {
  action = "deny"

  when all {
    tls_ja3 = [
      "62f6a6727fda5a1104d5b147cd82e520",
      # no-SNI
      "c53a2c34afdebeea3d08e9b86e555e7a",
    ]

    tls_ja4 = [
      "t13d4913h2_bd868743f55c_aac333855136",
      # no-SNI
      "t13i4912h2_bd868743f55c_aac333855136",
    ]

    http_http2 = ["3:1000;2:0;4:6291456;1:4096|15663105|0|s,m,p,a"]
  }
}