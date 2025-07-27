package proxy

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestSelfSignedCertSANs(t *testing.T) {
	tests := []struct {
		addr string
		host string
	}{
		{"192.168.0.1:0", "192.168.0.1"},
		{"example.com:0", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			cert, err := selfSignedCert(tt.addr)
			if err != nil {
				t.Fatalf("selfSignedCert: %v", err)
			}
			if len(cert.Certificate) == 0 {
				t.Fatalf("no certificate data")
			}
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("parse cert: %v", err)
			}

			foundDNS := false
			for _, dns := range parsed.DNSNames {
				if dns == tt.host {
					foundDNS = true
					break
				}
			}
			if ip := net.ParseIP(tt.host); ip != nil {
				foundIP := false
				for _, ipaddr := range parsed.IPAddresses {
					if ipaddr.Equal(ip) {
						foundIP = true
						break
					}
				}
				if !foundIP {
					t.Errorf("cert missing IP SAN for %s", tt.host)
				}
			} else if !foundDNS {
				t.Errorf("cert missing DNS SAN for %s", tt.host)
			}

			// check localhost DNS SAN
			haveLocalhost := false
			for _, dns := range parsed.DNSNames {
				if dns == "localhost" {
					haveLocalhost = true
					break
				}
			}
			if !haveLocalhost {
				t.Errorf("missing localhost SAN")
			}

			// check 127.0.0.1 and ::1 IP SANs
			wantIPs := []string{"127.0.0.1", "::1"}
			for _, w := range wantIPs {
				ip := net.ParseIP(w)
				found := false
				for _, ipaddr := range parsed.IPAddresses {
					if ipaddr.Equal(ip) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing IP SAN %s", w)
				}
			}

			pool := x509.NewCertPool()
			pool.AddCert(parsed)
			hosts := []string{tt.host, "localhost", "127.0.0.1", "::1"}
			for _, h := range hosts {
				if _, err := parsed.Verify(x509.VerifyOptions{DNSName: h, Roots: pool}); err != nil {
					t.Errorf("verify failed for %s: %v", h, err)
				}
			}
		})
	}
}
