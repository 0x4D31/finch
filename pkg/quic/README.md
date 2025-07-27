# QUIC clientHello Helper

This package exposes a tiny helper to extract the TLS ClientHello from a QUIC Initial packet. It is primarily used by Finch to fingerprint HTTP/3 clients, but it can be reused in other projects.

## Quick Start

```go
import "github.com/0x4D31/finch/pkg/quic"

func handleUDP(b []byte) {
    rec, err := quic.ExtractClientHello(b)
    if err == nil {
        fp := ja4.Fingerprint(rec) // use any JA3/JA4 library
        log.Println("JA4:", fp)
    }
}
```

The parser supports QUIC version 1 and 2 with either AES‑GCM or ChaCha20‑Poly1305 ciphers. It does not implement a full QUIC stack; it only decrypts the Initial packet and extracts the embedded TLS ClientHello. See [cmd/quic-chdump](/cmd/quic-chdump) for a real‑world example.