# HTTP/3 & QUIC (Experimental)

HTTP/3 and QUIC support in Finch is experimental. The QUIC parser decrypts the Initial packet, extracts CRYPTO frames and unmarshals the embedded TLS ClientHello to generate JA4 fingerprints. At the moment only clients built with the [`quic-go`](https://github.com/quic-go/quic-go) library have been tested successfully; other implementations (e.g. curl and Chrome) may fail the handshake.

The QUIC parsing logic lives in `pkg/quic` and can be reused independently. A small CLI tool ([quic-chdump](/cmd/quic-chdump/)) demonstrates how to extract ClientHello messages from live traffic or PCAPs and log the SNI and JA3/JA4 fingerprints.

## Sending an HTTP/3 Request via quic-go

```go
package main

import (
    "crypto/tls"
    "io"
    "log"
    "net/http"

    "github.com/quic-go/quic-go/http3"
)

func main() {
    tr := &http3.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
            NextProtos:         []string{http3.NextProtoH3},
        },
    }
    defer tr.Close()

    client := &http.Client{Transport: tr}
    resp, err := client.Get("https://localhost:8443/")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("%s", body)
}
```

Finch logs QUIC requests in the same JSONL format as HTTP/1 and HTTP/2 requests. Example log entry:

```
2025/07/20 16:06:57 INFO EVT: {"eventTime":"2025-07-20T15:06:57.104083Z","srcIP":"127.0.0.1","srcPort":52456,"dstIP":"::","dstPort":8443,"method":"GET","request":"/","headers":{"Accept-Encoding":"gzip","User-Agent":"quic-go HTTP/3"},"body":"","bodySha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","protocolVersion":"HTTP/3.0","userAgent":"quic-go HTTP/3","ja3":"799ef8161eed6e44249791020fdf7d36","ja4":"q13d0312h3_55b375c5d22e_c183556c78e2","ja4h":"ge30nn000000_000000000000_000000000000_000000000000","http2":"","ruleID":"default","action":"deny","upstream":"http://localhost:8080","listenerAddr":"0.0.0.0:8443"}
```