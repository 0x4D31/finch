//go:build pcap

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDumpPCAP(t *testing.T) {
	logFile := t.TempDir() + "/out.jsonl"
	cmd := exec.Command("go", "run", ".", "-r", "testdata/capture.pcap", "-f", "udp and port 8400", "-o", logFile, "-p")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := stripANSI(string(out))
	if !strings.Contains(s, "SNI:") || !strings.Contains(s, "JA3:") || !strings.Contains(s, "JA4:") {
		t.Fatalf("missing fields\n%s", out)
	}
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		t.Fatalf("log file empty")
	}
}

func TestAggregatedOutput(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-r", "testdata/capture.pcap", "-f", "udp and port 8400", "-p")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := stripANSI(string(out))
	if !strings.Contains(s, "SNI:") || !strings.Contains(s, "JA3:") || !strings.Contains(s, "JA4:") {
		t.Fatalf("missing fields\n%s", out)
	}
}

func stripANSI(s string) string {
	b := make([]byte, 0, len(s))
	esc := false
	for i := 0; i < len(s); i++ {
		if esc {
			if (s[i] >= '@' && s[i] <= '~') || s[i] == 'm' {
				esc = false
			}
			continue
		}
		if s[i] == 0x1b {
			esc = true
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}
