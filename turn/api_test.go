package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func startTestTURNAPI(t *testing.T, relay *openRelayPion, token string) *turnAPIServer {
	t.Helper()
	apiServer, err := startAPIServer(APIConfig{
		Listen: "127.0.0.1:0",
		Token:  token,
	}, relay)
	if err != nil {
		t.Fatalf("start api: %v", err)
	}
	if apiServer == nil {
		t.Fatal("api server not started")
	}
	t.Cleanup(func() {
		if err := apiServer.Close(); err != nil {
			t.Fatalf("close api: %v", err)
		}
	})
	return apiServer
}

func turnAPIRequest(t *testing.T, method, url, token string, body interface{}, out interface{}) int {
	t.Helper()
	var payload *bytes.Reader
	if body == nil {
		payload = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return resp.StatusCode
}

func TestTURNAPIRequiresBearerTokenAndListsUsers(t *testing.T) {
	server := newTestTURNServer(t, Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{{
			Username: "alice",
			Password: "alice-pass",
		}},
	})
	apiServer := startTestTURNAPI(t, server, "secret")
	baseURL := "http://" + apiServer.Addr().String()

	resp, err := http.Get(baseURL + "/v1/users")
	if err != nil {
		t.Fatalf("get without auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", resp.StatusCode)
	}

	var users []UserConfig
	if code := turnAPIRequest(t, http.MethodGet, baseURL+"/v1/users", "secret", nil, &users); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestTURNAPIUserAndPortRangeMutation(t *testing.T) {
	server := newTestTURNServer(t, Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
	})
	apiServer := startTestTURNAPI(t, server, "secret")
	baseURL := "http://" + apiServer.Addr().String()

	bob := UserConfig{
		Username: "bob",
		Password: "bob-pass",
		Port:     40100,
	}
	if code := turnAPIRequest(t, http.MethodPost, baseURL+"/v1/users", "secret", bob, nil); code != http.StatusOK {
		t.Fatalf("unexpected user create code %d", code)
	}
	if _, err := server.lookup("bob"); err != nil {
		t.Fatalf("lookup bob: %v", err)
	}

	portRange := RangeConfig{
		Start:    40200,
		End:      40202,
		Password: "range-pass",
	}
	if code := turnAPIRequest(t, http.MethodPost, baseURL+"/v1/port-ranges", "secret", portRange, nil); code != http.StatusOK {
		t.Fatalf("unexpected range create code %d", code)
	}
	if _, err := server.lookup("40201"); err != nil {
		t.Fatalf("lookup range credential: %v", err)
	}

	if code := turnAPIRequest(t, http.MethodDelete, baseURL+"/v1/users?username=bob", "secret", nil, nil); code != http.StatusNoContent {
		t.Fatalf("unexpected user delete code %d", code)
	}
	if _, err := server.lookup("bob"); err == nil {
		t.Fatal("expected bob to be removed")
	}

	if code := turnAPIRequest(t, http.MethodDelete, baseURL+"/v1/port-ranges?start=40200&end=40202", "secret", nil, nil); code != http.StatusNoContent {
		t.Fatalf("unexpected range delete code %d", code)
	}
	if _, err := server.lookup("40201"); err == nil {
		t.Fatal("expected range credential to be removed")
	}
}

func TestTURNAPIStatusIncludesActiveSession(t *testing.T) {
	server := newTestTURNServer(t, Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			SourceNetworks: []string{"127.0.0.0/8"},
		}},
	})
	apiServer := startTestTURNAPI(t, server, "secret")
	baseURL := "http://" + apiServer.Addr().String()

	client := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	relayConn := allocateRelay(t, client)
	defer relayConn.Close()

	var status apiStatusSnapshot
	if code := turnAPIRequest(t, http.MethodGet, baseURL+"/v1/status", "secret", nil, &status); code != http.StatusOK {
		t.Fatalf("unexpected status code %d", code)
	}
	if status.GlobalSessions < 1 {
		t.Fatalf("expected active session count, got %+v", status)
	}
	found := false
	for _, sess := range status.Sessions {
		if sess.Username == "alice" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected alice session in status: %+v", status.Sessions)
	}
}
