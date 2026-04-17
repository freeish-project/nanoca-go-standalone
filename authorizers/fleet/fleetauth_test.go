package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/freeish-project/nanoca"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestAuthorize_HostFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/hosts" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		query := r.URL.Query().Get("query")
		resp := hostsResponse{
			Hosts: []host{
				{HardwareSerial: query, UUID: "uuid-123"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	auth := New(testLogger(), server.URL, "test-token")
	device := &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "SERIAL123",
		},
	}

	ok, err := auth.Authorize(context.Background(), device)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected authorized, got denied")
	}
}

func TestAuthorize_HostNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := hostsResponse{Hosts: []host{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	auth := New(testLogger(), server.URL, "test-token")
	device := &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "UNKNOWN",
		},
	}

	ok, err := auth.Authorize(context.Background(), device)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected denied, got authorized")
	}
}

func TestAuthorize_MatchByUUID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := hostsResponse{
			Hosts: []host{
				{HardwareSerial: "DIFFERENT", UUID: "uuid-456"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	auth := New(testLogger(), server.URL, "test-token")
	device := &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "uuid-456",
		},
	}

	ok, err := auth.Authorize(context.Background(), device)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected authorized via UUID match, got denied")
	}
}

func TestAuthorize_NilDevice(t *testing.T) {
	auth := New(testLogger(), "http://unused", "token")

	ok, err := auth.Authorize(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected denied for nil device, got authorized")
	}
}

func TestAuthorize_NoPermanentIdentifier(t *testing.T) {
	auth := New(testLogger(), "http://unused", "token")

	ok, err := auth.Authorize(context.Background(), &nanoca.DeviceInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected denied for missing identifier, got authorized")
	}
}

func TestAuthorize_FleetAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	auth := New(testLogger(), server.URL, "test-token")
	device := &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "SERIAL123",
		},
	}

	ok, err := auth.Authorize(context.Background(), device)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if ok {
		t.Fatal("expected denied on API error")
	}
}

func TestAuthorize_FleetUnreachable(t *testing.T) {
	auth := New(testLogger(), "http://127.0.0.1:1", "test-token")
	device := &nanoca.DeviceInfo{
		PermanentIdentifier: &nanoca.PermanentIdentifier{
			Identifier: "SERIAL123",
		},
	}

	ok, err := auth.Authorize(context.Background(), device)
	if err == nil {
		t.Fatal("expected error for unreachable Fleet")
	}
	if ok {
		t.Fatal("expected denied when Fleet unreachable")
	}
}
