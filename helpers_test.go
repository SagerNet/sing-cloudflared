package cloudflared

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

func requireEnvVars(t *testing.T) (token string, testURL string) {
	t.Helper()
	token = os.Getenv("CF_TUNNEL_TOKEN")
	testURL = os.Getenv("CF_TEST_URL")
	if token == "" || testURL == "" {
		t.Skip("CF_TUNNEL_TOKEN and CF_TEST_URL must be set")
	}
	return
}

var startOriginServerOnce sync.Once

func startOriginServer(t *testing.T) {
	t.Helper()
	startOriginServerOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
		})
		mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			io.Copy(w, r.Body)
		})
		mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
			codeStr := strings.TrimPrefix(r.URL.Path, "/status/")
			code, err := strconv.Atoi(codeStr)
			if err != nil {
				code = 200
			}
			w.Header().Set("X-Custom", "test-value")
			w.WriteHeader(code)
			fmt.Fprintf(w, "status: %d", code)
		})
		mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(r.Header)
		})

		server := &http.Server{
			Addr:    "127.0.0.1:8083",
			Handler: mux,
		}

		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			t.Fatal("start origin server: ", err)
		}

		go server.Serve(listener)
	})
}

type testHandler struct{}

func (h *testHandler) DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return net.Dial("tcp", destination.String())
}

func (h *testHandler) DialPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	conn, err := net.Dial("udp", destination.String())
	if err != nil {
		return nil, err
	}
	return conn.(N.PacketConn), nil
}

func testToken(t *testing.T) string {
	t.Helper()
	tunnelID := uuid.New()
	secret := []byte("test-secret-32-bytes-long-xxxxx")
	tokenJSON := `{"a":"test-account","t":"` + tunnelID.String() + `","s":"` + base64.StdEncoding.EncodeToString(secret) + `"}`
	return base64.StdEncoding.EncodeToString([]byte(tokenJSON))
}

func newTestService(t *testing.T, token string, protocol string, haConnections int) *Service {
	t.Helper()
	credentials, err := parseToken(token)
	if err != nil {
		t.Fatal("parse token: ", err)
	}

	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal("create config manager: ", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serviceInstance := &Service{
		ctx:                 ctx,
		cancel:              cancel,
		handler:             &testHandler{},
		logger:              logger.NOP(),
		credentials:         credentials,
		connectorID:         uuid.New(),
		haConnections:       haConnections,
		protocol:            protocol,
		edgeIPVersion:       0,
		datagramVersion:     "",
		featureSelector:     newFeatureSelector(ctx, credentials.AccountTag, ""),
		gracePeriod:         5 * time.Second,
		configManager:       configManager,
		datagramV2Muxers:    make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers:    make(map[DatagramSender]*DatagramV3Muxer),
		datagramV3Manager:   NewDatagramV3SessionManager(),
		connectedIndices:    make(map[uint8]struct{}),
		connectedNotify:     make(chan uint8, haConnections),
		controlDialer:       N.SystemDialer,
		tunnelDialer:        N.SystemDialer,
		accessCache:         &accessValidatorCache{values: make(map[string]accessValidator), dialer: N.SystemDialer},
		connectionStates:    make([]connectionState, haConnections),
		successfulProtocols: make(map[string]struct{}),
		directTransports:    make(map[string]*http.Transport),
	}

	t.Cleanup(func() {
		cancel()
		serviceInstance.Close()
	})
	return serviceInstance
}

func waitForTunnel(t *testing.T, testURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	var lastStatus int
	var lastBody string
	for time.Now().Before(deadline) {
		resp, err := client.Get(testURL + "/ping")
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = string(body)
		if resp.StatusCode == http.StatusOK && lastBody == `{"ok":true}` {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("tunnel not ready after %s (lastErr=%v, lastStatus=%d, lastBody=%q)", timeout, lastErr, lastStatus, lastBody)
}
