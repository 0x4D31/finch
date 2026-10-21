# Reusing Finch fingerprints and access logs

Custom handlers can reuse Finch's fingerprint extraction, access-event schema and JSONL writer without running its CLI, rule engine or Galah service. These public packages are small facades over the same implementation used by Finch, not independent copies.

## Packages

- `github.com/0x4D31/finch/pkg/fingerprint`: `New(*http.Request)` returns the observed JA3, raw JA3, JA4, JA4H and HTTP/2 fingerprints plus request metadata.
- `github.com/0x4D31/finch/pkg/logger`: `Event`, its related types/action constants, `New`, `NewWithStdout` and `NewRequestEvent` expose the standard access-log format and writer.
- `github.com/0x4D31/fingerproxy/pkg/proxyserver`: the existing public listener used underneath Finch supplies ClientHello, header-order and HTTP/2 metadata to custom HTTP handlers.

Use `proxyserver.NewServer(ctx, handler, tlsConfig)` and its `Serve(net.Listener)` or `ListenAndServe(address)` method for TLS HTTP/1.1 and HTTP/2. Configure certificates, ALPN, handshake/request timeouts and resource limits before serving; do not replace its metadata-collecting connection hooks.

An ordinary `net/http` TLS listener does not collect the required fingerprint metadata. Client-supplied `X-JA*` headers are not a substitute.

## Building an event in a custom handler

```go
import (
    "net/http"

    "github.com/0x4D31/finch/pkg/fingerprint"
    "github.com/0x4D31/finch/pkg/logger"
)

func recordRequest(log *logger.Logger, r *http.Request, capturedBody []byte) error {
    fp, fpErr := fingerprint.New(r)
    event := logger.NewRequestEvent(r, fp, capturedBody)
    event.Action = logger.ActionDeceive
    event.ListenerAddr = "127.0.0.1:8443"
    if fpErr != nil {
        event.Error = fpErr.Error()
    }
    return log.Log(event)
}
```

`NewRequestEvent` does not read or replace the request body. Supply the bytes captured by your application's bounded capture path, then handle the logging error before proceeding according to your application's policy.

The builder populates Finch's existing request fields, including socket addresses, request URL, joined header values, body hash and fingerprints. The application supplies action/rule/listener details and any response-specific observations.

## Semantics and limits

- No fingerprint metadata means empty fingerprint fields, not a fingerprint inferred from the user agent or forwarded headers.
- `bodySha256` hashes exactly the supplied bytes. A truncated capture produces a prefix hash; the application must track completeness and truncation separately.
- The legacy `headers` field joins repeated values with commas, and `body` is a JSON string. Preserve raw binary bodies and multi-value headers separately when lossless evidence matters.
- Creating or persisting a request event does not demonstrate response delivery, execution or exploit success.
- The logger retains its existing append behavior and file permissions. Use a private parent directory or pre-created private file for sensitive evidence, check errors, and own retention/durability policy in the application.
- The public logger is not a body limiter, event-retention manager or safe-execution sandbox. These policies belong to the embedding application.
- This composition covers TLS HTTP/1.1 and HTTP/2. Finch's HTTP/3 adapter and administrative/runtime APIs are not exported by these packages.

The public-package integration tests exercise real TLS HTTP/1.1 and HTTP/2 clients with a custom handler, nonempty fingerprints, spoofed fingerprint headers, a binary request body, explicit status and repeated response cookies. Existing Finch request logging uses the same event builder.
