package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandler(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sba-ca.crl"), []byte("crl"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.crl"), 0o755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler(dir, &logger{}))
	defer server.Close()

	cases := []struct {
		method, path string
		status       int
		body         string
	}{
		{http.MethodGet, "/sba-ca.crl", http.StatusOK, "crl"},
		{http.MethodHead, "/sba-ca.crl", http.StatusOK, ""},
		{http.MethodPost, "/sba-ca.crl", http.StatusMethodNotAllowed, ""},
		{http.MethodGet, "/other.crl", http.StatusNotFound, ""},
		{http.MethodGet, "/", http.StatusNotFound, ""},
		{http.MethodGet, "/secret.key", http.StatusNotFound, ""},
		{http.MethodGet, "/sub.crl", http.StatusNotFound, ""},
		{http.MethodGet, "/%2e%2e/sba-ca.crl", http.StatusNotFound, ""},
		{http.MethodGet, "/sub.crl/../sba-ca.crl", http.StatusNotFound, ""},
	}
	for _, c := range cases {
		req, err := http.NewRequest(c.method, server.URL+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		var body strings.Builder
		buf := make([]byte, 16)
		n, _ := resp.Body.Read(buf)
		body.Write(buf[:n])
		_ = resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Errorf("%s %s: status %d, want %d", c.method, c.path, resp.StatusCode, c.status)
		}
		if c.status == http.StatusOK {
			if got := resp.Header.Get("Content-Type"); got != "application/pkix-crl" {
				t.Errorf("%s %s: Content-Type %q", c.method, c.path, got)
			}
			if body.String() != c.body {
				t.Errorf("%s %s: body %q", c.method, c.path, body.String())
			}
		}
		if c.status == http.StatusMethodNotAllowed && resp.Header.Get("Allow") == "" {
			t.Errorf("%s %s: no Allow header", c.method, c.path)
		}
	}
}

func TestReadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crlcfg.yaml")
	if err := os.WriteFile(path, []byte("configuration:\n  bindingIPv4: 127.0.0.1\n  port: 8030\n  directory: cert/crl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Configuration.Port != 8030 {
		t.Errorf("port %d", cfg.Configuration.Port)
	}
	if err = os.WriteFile(path, []byte("configuration:\n  port: 8030\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = readConfig(path); err == nil {
		t.Error("configuration without address and directory accepted")
	}
}
