// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIClientCommands(t *testing.T) {
	type hit struct {
		method string
		path   string
		query  string
		body   string
	}
	var hits []hit
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("authorization header = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		hits = append(hits, hit{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(body)})
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status":
			_, _ = w.Write([]byte(`{"listen_port":51820}`))
		case "/v1/ping":
			if r.URL.Query().Get("target") == "" {
				t.Fatalf("missing ping target")
			}
			_, _ = w.Write([]byte(`{"transmitted":1,"received":1}`))
		case "/v1/interface_ips":
			_, _ = w.Write([]byte(`["100.64.0.2"]`))
		case "/v1/peers":
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`[]`))
			case http.MethodPost:
				requireJSONField(t, body, "public_key")
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				if r.URL.Query().Get("public_key") == "" {
					t.Fatalf("missing peer public_key")
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected peers method %s", r.Method)
			}
		case "/v1/acls/outbound":
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`[]`))
			case http.MethodPost:
				requireJSONField(t, body, "action")
				w.WriteHeader(http.StatusNoContent)
			case http.MethodPut:
				var rules []any
				if err := json.Unmarshal(body, &rules); err != nil {
					t.Fatal(err)
				}
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				if r.URL.Query().Get("index") == "" {
					t.Fatalf("missing ACL index")
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected ACL method %s", r.Method)
			}
		case "/v1/wireguard/config":
			if r.Method != http.MethodPut || !strings.Contains(string(body), "[Interface]") {
				t.Fatalf("bad wg-setconf request")
			}
			w.WriteHeader(http.StatusNoContent)
		case "/v1/forwards":
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`[]`))
			case http.MethodPost:
				requireJSONField(t, body, "listen")
				_, _ = w.Write([]byte(`{"name":"forward.runtime.1","listen":"127.0.0.1:18080","target":"100.64.0.1:80"}`))
			case http.MethodDelete:
				if r.URL.Query().Get("name") == "" {
					t.Fatalf("missing forward name")
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected forwards method %s", r.Method)
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv("UWGS_API", server.URL)
	t.Setenv("UWGS_API_TOKEN", "secret")
	tmp := t.TempDir()
	aclFile := filepath.Join(tmp, "acl.json")
	if err := os.WriteFile(aclFile, []byte(`[{"action":"allow"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	wgFile := filepath.Join(tmp, "wg.conf")
	if err := os.WriteFile(wgFile, []byte("[Interface]\nPrivateKey = TEST\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	commands := [][]string{
		{"status"},
		{"ping", "100.64.0.1", "--count", "1"},
		{"interface-ips"},
		{"peers"},
		{"add-peer", "--public-key", "peerkey", "--allowed-ip", "100.64.0.3/32"},
		{"remove-peer", "peerkey"},
		{"acl-list", "outbound"},
		{"acl-add", "outbound", "allow dst=100.64.0.0/24"},
		{"acl-set", "--file", aclFile, "outbound"},
		{"acl-remove", "--index", "0", "outbound"},
		{"wg-setconf", wgFile},
		{"forwards"},
		{"add-forward", "--proto", "tcp", "--listen", "127.0.0.1:18080", "--target", "100.64.0.1:80"},
		{"remove-forward", "forward.runtime.1"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if _, err := captureStdout(func() error {
				handled, err := runAPICommand(args)
				if !handled {
					t.Fatalf("command %q was not handled", args[0])
				}
				return err
			}); err != nil {
				t.Fatalf("%v failed: %v", args, err)
			}
		})
	}

	if len(hits) != len(commands) {
		t.Fatalf("got %d API hits, want %d", len(hits), len(commands))
	}
	if got := hits[len(hits)-1].query; got != "name="+url.QueryEscape("forward.runtime.1") {
		t.Fatalf("remove-forward query = %q", got)
	}
}

func requireJSONField(t *testing.T, body []byte, field string) {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if _, ok := v[field]; !ok {
		t.Fatalf("missing JSON field %q in %s", field, body)
	}
}

func captureStdout(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	err = fn()
	_ = w.Close()
	out, readErr := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		return string(out), err
	}
	return string(out), readErr
}
