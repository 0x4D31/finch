package proxy

import (
    "crypto/tls"
    "net"
    "net/http"
    "net/http/httptest"
    "net/url"
    "testing"
    "time"

    "github.com/0x4D31/finch/internal/logger"
    "github.com/0x4D31/finch/internal/rules"
)

// These tests cover default-upstream base-path mapping semantics when no rule matches.
func TestDefaultUpstream_BasePathRoot(t *testing.T) {
    var gotPath, gotQuery string
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
        w.WriteHeader(http.StatusOK)
    }))
    defer backend.Close()

    u, _ := url.Parse(backend.URL)
    u.Path = "/anything"

    lgr, err := logger.New(t.TempDir() + "/events.jsonl")
    if err != nil { t.Fatalf("new logger: %v", err) }
    defer lgr.Close()

    eng := &rules.Engine{DefaultAction: rules.ActionAllow}

    svr, err := New("test", "127.0.0.1:0", u.String(), "", "", lgr, eng, nil, nil, nil, nil, "", false)
    if err != nil { t.Fatalf("new server: %v", err) }

    ln, err := net.Listen("tcp", svr.ListenAddr)
    if err != nil { t.Fatalf("listen: %v", err) }
    defer ln.Close()
    go func() { _ = svr.Serve(ln) }()
    time.Sleep(50 * time.Millisecond)

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + ln.Addr().String() + "/")
    if err != nil { t.Fatalf("client get: %v", err) }
    _ = resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }
    if gotPath != "/anything" {
        t.Fatalf("path want /anything got %s", gotPath)
    }
    if gotQuery != "" {
        t.Fatalf("query want empty got %s", gotQuery)
    }
}

func TestDefaultUpstream_BasePathSubpath(t *testing.T) {
    var gotPath, gotQuery string
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
        w.WriteHeader(http.StatusOK)
    }))
    defer backend.Close()

    u, _ := url.Parse(backend.URL)
    u.Path = "/anything"

    lgr, err := logger.New(t.TempDir() + "/events.jsonl")
    if err != nil { t.Fatalf("new logger: %v", err) }
    defer lgr.Close()

    eng := &rules.Engine{DefaultAction: rules.ActionAllow}

    svr, err := New("test", "127.0.0.1:0", u.String(), "", "", lgr, eng, nil, nil, nil, nil, "", false)
    if err != nil { t.Fatalf("new server: %v", err) }

    ln, err := net.Listen("tcp", svr.ListenAddr)
    if err != nil { t.Fatalf("listen: %v", err) }
    defer ln.Close()
    go func() { _ = svr.Serve(ln) }()
    time.Sleep(50 * time.Millisecond)

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + ln.Addr().String() + "/foo")
    if err != nil { t.Fatalf("client get: %v", err) }
    _ = resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }
    if gotPath != "/anything/foo" {
        t.Fatalf("path want /anything/foo got %s", gotPath)
    }
    if gotQuery != "" {
        t.Fatalf("query want empty got %s", gotQuery)
    }
}

func TestDefaultUpstream_HttpbinStyleFixedRoot(t *testing.T) {
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        status := http.StatusNotFound
        if r.URL.Path == "/anything" {
            status = http.StatusOK
        }
        w.WriteHeader(status)
    }))
    defer backend.Close()

    u, _ := url.Parse(backend.URL)
    u.Path = "/anything"

    lgr, err := logger.New(t.TempDir() + "/events.jsonl")
    if err != nil { t.Fatalf("new logger: %v", err) }
    defer lgr.Close()

    eng := &rules.Engine{DefaultAction: rules.ActionAllow}

    svr, err := New("test", "127.0.0.1:0", u.String(), "", "", lgr, eng, nil, nil, nil, nil, "", false)
    if err != nil { t.Fatalf("new server: %v", err) }

    ln, err := net.Listen("tcp", svr.ListenAddr)
    if err != nil { t.Fatalf("listen: %v", err) }
    defer ln.Close()
    go func() { _ = svr.Serve(ln) }()
    time.Sleep(50 * time.Millisecond)

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + ln.Addr().String() + "/")
    if err != nil { t.Fatalf("client get: %v", err) }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }
}

func TestDefaultUpstream_QueryMerge(t *testing.T) {
    var gotPath, gotQuery string
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
        w.WriteHeader(http.StatusOK)
    }))
    defer backend.Close()

    u, _ := url.Parse(backend.URL)
    u.Path = "/anything"
    u.RawQuery = "version=1"

    lgr, err := logger.New(t.TempDir() + "/events.jsonl")
    if err != nil { t.Fatalf("new logger: %v", err) }
    defer lgr.Close()

    eng := &rules.Engine{DefaultAction: rules.ActionAllow}

    svr, err := New("test", "127.0.0.1:0", u.String(), "", "", lgr, eng, nil, nil, nil, nil, "", false)
    if err != nil { t.Fatalf("new server: %v", err) }

    ln, err := net.Listen("tcp", svr.ListenAddr)
    if err != nil { t.Fatalf("listen: %v", err) }
    defer ln.Close()
    go func() { _ = svr.Serve(ln) }()
    time.Sleep(50 * time.Millisecond)

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + ln.Addr().String() + "/foo?user=abc")
    if err != nil { t.Fatalf("client get: %v", err) }
    _ = resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }

    if gotPath != "/anything/foo" {
        t.Fatalf("path want /anything/foo got %s", gotPath)
    }
    // Order-insensitive; just check both keys exist
    if gotQuery != "version=1&user=abc" && gotQuery != "user=abc&version=1" {
        t.Fatalf("query want version=1&user=abc (any order), got %s", gotQuery)
    }
}

func TestDefaultUpstream_NoBasePathNoop(t *testing.T) {
    var gotPath string
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotPath = r.URL.Path
        w.WriteHeader(http.StatusOK)
    }))
    defer backend.Close()

    lgr, err := logger.New(t.TempDir() + "/events.jsonl")
    if err != nil { t.Fatalf("new logger: %v", err) }
    defer lgr.Close()

    eng := &rules.Engine{DefaultAction: rules.ActionAllow}

    svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
    if err != nil { t.Fatalf("new server: %v", err) }

    ln, err := net.Listen("tcp", svr.ListenAddr)
    if err != nil { t.Fatalf("listen: %v", err) }
    defer ln.Close()
    go func() { _ = svr.Serve(ln) }()
    time.Sleep(50 * time.Millisecond)

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + ln.Addr().String() + "/bar")
    if err != nil { t.Fatalf("client get: %v", err) }
    _ = resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }
    if gotPath != "/bar" {
        t.Fatalf("path want /bar got %s", gotPath)
    }
}

func TestDefaultUpstream_TrailingSlashPreserved(t *testing.T) {
    var gotPath string
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotPath = r.URL.Path
        w.WriteHeader(http.StatusOK)
    }))
    defer backend.Close()

    u, _ := url.Parse(backend.URL)
    u.Path = "/anything/"

    lgr, err := logger.New(t.TempDir() + "/events.jsonl")
    if err != nil { t.Fatalf("new logger: %v", err) }
    defer lgr.Close()

    eng := &rules.Engine{DefaultAction: rules.ActionAllow}

    svr, err := New("test", "127.0.0.1:0", u.String(), "", "", lgr, eng, nil, nil, nil, nil, "", false)
    if err != nil { t.Fatalf("new server: %v", err) }

    ln, err := net.Listen("tcp", svr.ListenAddr)
    if err != nil { t.Fatalf("listen: %v", err) }
    defer ln.Close()
    go func() { _ = svr.Serve(ln) }()
    time.Sleep(50 * time.Millisecond)

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + ln.Addr().String() + "/")
    if err != nil { t.Fatalf("client get: %v", err) }
    _ = resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }

    if gotPath != "/anything/" {
        t.Fatalf("path want /anything/ got %s", gotPath)
    }
}
