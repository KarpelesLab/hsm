package yubihsm2

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHTTPConnector(t *testing.T) {
	url := "localhost:12345"
	connector := NewHTTPConnector(url)

	if connector.URL != url {
		t.Errorf("URL = %q, want %q", connector.URL, url)
	}

	if connector.client == nil {
		t.Error("client should not be nil")
	}

	if connector.client.Timeout != defaultHTTPTimeout {
		t.Errorf("Timeout = %v, want %v", connector.client.Timeout, defaultHTTPTimeout)
	}
}

func TestHTTPConnectorRequest(t *testing.T) {
	// Create a test server
	expectedResponse := []byte{0x81, 0x00, 0x03, 0x01, 0x02, 0x03}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connector/api" {
			t.Errorf("Path = %q, want /connector/api", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Method = %q, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Errorf("Content-Type = %q, want application/octet-stream", r.Header.Get("Content-Type"))
		}
		w.Write(expectedResponse)
	}))
	defer server.Close()

	// Extract host:port from server URL
	url := strings.TrimPrefix(server.URL, "http://")
	connector := NewHTTPConnector(url)

	cmd := CmdEcho.New()
	cmd.Write([]byte{0x01, 0x02, 0x03})

	response, err := connector.Request(cmd)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if string(response) != string(expectedResponse) {
		t.Errorf("Response = %v, want %v", response, expectedResponse)
	}
}

func TestHTTPConnectorRequestError(t *testing.T) {
	// Create a test server that returns an error status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	url := strings.TrimPrefix(server.URL, "http://")
	connector := NewHTTPConnector(url)

	cmd := CmdEcho.New()
	_, err := connector.Request(cmd)
	if err == nil {
		t.Error("Expected error for non-OK status")
	}
}

func TestHTTPConnectorGetStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connector/status" {
			t.Errorf("Path = %q, want /connector/status", r.URL.Path)
		}
		w.Write([]byte("status=OK\nserial=12345678\nversion=3.0.0\npid=1234\naddress=127.0.0.1\nport=12345\n"))
	}))
	defer server.Close()

	url := strings.TrimPrefix(server.URL, "http://")
	connector := NewHTTPConnector(url)

	status, err := connector.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}

	if status.Status != "OK" {
		t.Errorf("Status = %q, want OK", status.Status)
	}
	if status.Serial != "12345678" {
		t.Errorf("Serial = %q, want 12345678", status.Serial)
	}
	if status.Version != "3.0.0" {
		t.Errorf("Version = %q, want 3.0.0", status.Version)
	}
	if status.Pid != "1234" {
		t.Errorf("Pid = %q, want 1234", status.Pid)
	}
	if status.Address != "127.0.0.1" {
		t.Errorf("Address = %q, want 127.0.0.1", status.Address)
	}
	if status.Port != "12345" {
		t.Errorf("Port = %q, want 12345", status.Port)
	}
}

func TestHTTPConnectorConnectionRefused(t *testing.T) {
	connector := NewHTTPConnector("localhost:59999") // Unlikely to be in use

	cmd := CmdEcho.New()
	_, err := connector.Request(cmd)
	if err == nil {
		t.Error("Expected error for connection refused")
	}
}
