package cloudflared

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

const (
	liveTestsEnv          = "CF_LIVE_TESTS"
	legacyTunnelTokenEnv  = "CF_TUNNEL_TOKEN"
	legacyTestURLEnv      = "CF_TEST_URL"
	cloudflareAPITokenEnv = "CF_API_TOKEN"
	cloudflareAccountEnv  = "CF_ACCOUNT_ID"
	cloudflareZoneIDEnv   = "CF_ZONE_ID"
	cloudflareZoneNameEnv = "CF_ZONE_NAME"
	cloudflareHostnameEnv = "CF_TEST_HOSTNAME"
	liveTestDebugEnv      = "CF_LIVE_TEST_DEBUG"

	legacyOriginListenAddr = "127.0.0.1:8083"
	cloudflareAPIBaseURL   = "https://api.cloudflare.com/client/v4"
)

type liveTestMode string

const (
	liveTestModeLegacy      liveTestMode = "legacy"
	liveTestModeProvisioned liveTestMode = "provisioned"
)

type liveTestEnvironment struct {
	mode     liveTestMode
	token    string
	baseURL  string
	hostname string

	origin    *testOriginServer
	resources *cloudflareLiveResources
}

func (e *liveTestEnvironment) HTTPURL(path string) string {
	return strings.TrimRight(e.baseURL, "/") + path
}

func (e *liveTestEnvironment) WebSocketURL(path string) string {
	parsedURL, err := url.Parse(e.baseURL)
	if err != nil {
		panic(err)
	}
	switch parsedURL.Scheme {
	case "https":
		parsedURL.Scheme = "wss"
	default:
		parsedURL.Scheme = "ws"
	}
	parsedURL.Path = path
	parsedURL.RawPath = ""
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return parsedURL.String()
}

func (e *liveTestEnvironment) Close() error {
	var errs []string
	if e.resources != nil {
		if err := e.resources.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if e.origin != nil {
		if err := e.origin.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

type testOriginRequest struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	Headers http.Header `json:"headers"`
}

type testOriginServer struct {
	server   *http.Server
	listener net.Listener
	baseURL  string
}

func newTestOriginServer(listenAddr string) (*testOriginServer, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, r.Body)
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		codeStr := strings.TrimPrefix(r.URL.Path, "/status/")
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			code = http.StatusOK
		}
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(code)
		_, _ = fmt.Fprintf(w, "status: %d", code)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(testOriginRequest{
			Method:  r.Method,
			Host:    r.Host,
			Headers: r.Header.Clone(),
		})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			payload, opCode, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			if err := wsutil.WriteServerMessage(conn, opCode, payload); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		count := 50
		if countText := r.URL.Query().Get("count"); countText != "" {
			if parsedCount, err := strconv.Atoi(countText); err == nil && parsedCount > 0 {
				count = parsedCount
			}
		}
		interval := 200 * time.Millisecond
		if intervalText := r.URL.Query().Get("interval_ms"); intervalText != "" {
			if parsedInterval, err := strconv.Atoi(intervalText); err == nil && parsedInterval > 0 {
				interval = time.Duration(parsedInterval) * time.Millisecond
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		timer := time.NewTimer(interval)
		defer timer.Stop()
		for index := 1; index <= count; index++ {
			if _, err := fmt.Fprintf(w, "data: %d\n\n", index); err != nil {
				return
			}
			flusher.Flush()

			if index == count {
				return
			}

			select {
			case <-r.Context().Done():
				return
			case <-timer.C:
				timer.Reset(interval)
			}
		}
	})

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "test origin server failed: %v\n", err)
		}
	}()

	return &testOriginServer{
		server:   server,
		listener: listener,
		baseURL:  "http://" + listener.Addr().String(),
	}, nil
}

func (s *testOriginServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

type cloudflareProvisioningConfig struct {
	apiToken  string
	accountID string
	zoneID    string
	zoneName  string
	hostname  string
}

type cloudflareLiveResources struct {
	client *cloudflareAPITestClient

	tunnelID string
	hostname string
}

func (r *cloudflareLiveResources) Close() error {
	var errs []string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if r.tunnelID != "" {
		if err := r.client.deleteTunnel(ctx, r.tunnelID); err != nil {
			errs = append(errs, fmt.Sprintf("delete tunnel %s: %v", r.tunnelID, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

type cloudflareAPITestClient struct {
	accountID string
	zoneID    string
	apiToken  string
	baseURL   string
	client    *http.Client
}

type cloudflareAPIEnvelope struct {
	Success bool                 `json:"success"`
	Errors  []cloudflareAPIError `json:"errors"`
	Result  json.RawMessage      `json:"result"`
}

type cloudflareAPIError struct {
	Code    any    `json:"code"`
	Message string `json:"message"`
}

type cloudflareAPICallError struct {
	StatusCode int
	Message    string
}

func (e *cloudflareAPICallError) Error() string {
	return e.Message
}

func newCloudflareAPITestClient(config cloudflareProvisioningConfig) *cloudflareAPITestClient {
	return &cloudflareAPITestClient{
		accountID: config.accountID,
		zoneID:    config.zoneID,
		apiToken:  config.apiToken,
		baseURL:   cloudflareAPIBaseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *cloudflareAPITestClient) call(ctx context.Context, method string, path string, body any, result any) error {
	var bodyData []byte
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyData = data
	}

	const maxAttempts = 3
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		var requestBody io.Reader
		if bodyData != nil {
			requestBody = strings.NewReader(string(bodyData))
		}

		request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, requestBody)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+c.apiToken)
		request.Header.Set("Accept", "application/json")
		if bodyData != nil {
			request.Header.Set("Content-Type", "application/json")
		}

		response, err := c.client.Do(request)
		if err != nil {
			return err
		}

		envelope := cloudflareAPIEnvelope{}
		decodeErr := json.NewDecoder(response.Body).Decode(&envelope)
		response.Body.Close()

		if decodeErr != nil {
			return &cloudflareAPICallError{
				StatusCode: response.StatusCode,
				Message:    fmt.Sprintf("%s %s returned %d with invalid JSON: %v", method, path, response.StatusCode, decodeErr),
			}
		}

		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			var errorMessages []string
			for _, apiErr := range envelope.Errors {
				switch {
				case apiErr.Code != nil:
					errorMessages = append(errorMessages, fmt.Sprintf("%v: %s", apiErr.Code, apiErr.Message))
				case apiErr.Message != "":
					errorMessages = append(errorMessages, apiErr.Message)
				}
			}
			if len(errorMessages) == 0 {
				errorMessages = append(errorMessages, "unknown API error")
			}
			callErr := &cloudflareAPICallError{
				StatusCode: response.StatusCode,
				Message:    fmt.Sprintf("%s %s returned %d: %s", method, path, response.StatusCode, strings.Join(errorMessages, "; ")),
			}
			if response.StatusCode >= 500 {
				lastErr = callErr
				continue
			}
			return callErr
		}

		if !envelope.Success {
			var errorMessages []string
			for _, apiErr := range envelope.Errors {
				switch {
				case apiErr.Code != nil:
					errorMessages = append(errorMessages, fmt.Sprintf("%v: %s", apiErr.Code, apiErr.Message))
				case apiErr.Message != "":
					errorMessages = append(errorMessages, apiErr.Message)
				}
			}
			if len(errorMessages) == 0 {
				errorMessages = append(errorMessages, "unsuccessful Cloudflare API response")
			}
			return fmt.Errorf("%s %s: %s", method, path, strings.Join(errorMessages, "; "))
		}

		if result == nil || len(envelope.Result) == 0 || string(envelope.Result) == "null" {
			return nil
		}
		return json.Unmarshal(envelope.Result, result)
	}
	return lastErr
}

type cloudflareCreatedTunnel struct {
	ID string `json:"id"`
}

func (c *cloudflareAPITestClient) createTunnel(ctx context.Context, name string) (cloudflareCreatedTunnel, error) {
	var tunnel cloudflareCreatedTunnel
	err := c.call(ctx, http.MethodPost,
		fmt.Sprintf("/accounts/%s/cfd_tunnel", c.accountID),
		map[string]any{
			"name":       name,
			"config_src": "cloudflare",
		},
		&tunnel,
	)
	return tunnel, err
}

func (c *cloudflareAPITestClient) getTunnelToken(ctx context.Context, tunnelID string) (string, error) {
	var token string
	err := c.call(ctx, http.MethodGet,
		fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/token", c.accountID, tunnelID),
		nil,
		&token,
	)
	return token, err
}

func (c *cloudflareAPITestClient) updateTunnelConfiguration(ctx context.Context, tunnelID string, hostname string, serviceURL string) error {
	requestBody := map[string]any{
		"config": map[string]any{
			"ingress": []map[string]any{
				{
					"hostname": hostname,
					"service":  serviceURL,
				},
				{
					"service": "http_status:404",
				},
			},
		},
	}

	path := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", c.accountID, tunnelID)
	err := c.call(ctx, http.MethodPatch, path, requestBody, nil)
	if err == nil {
		return nil
	}

	apiErr, ok := err.(*cloudflareAPICallError)
	if !ok || apiErr.StatusCode != http.StatusMethodNotAllowed {
		return err
	}
	return c.call(ctx, http.MethodPut, path, requestBody, nil)
}

type cloudflareTunnelDNSRouteResult struct {
	CNAME  string `json:"cname"`
	Name   string `json:"name"`
	DNSTag string `json:"dns_tag"`
}

func (c *cloudflareAPITestClient) routeTunnelDNS(ctx context.Context, tunnelID string, hostname string) (cloudflareTunnelDNSRouteResult, error) {
	var result cloudflareTunnelDNSRouteResult
	err := c.call(ctx, http.MethodPut,
		fmt.Sprintf("/zones/%s/tunnels/%s/routes", c.zoneID, tunnelID),
		map[string]any{
			"type":               "dns",
			"user_hostname":      hostname,
			"overwrite_existing": true,
		},
		&result,
	)
	return result, err
}

func (c *cloudflareAPITestClient) deleteTunnel(ctx context.Context, tunnelID string) error {
	return c.call(ctx, http.MethodDelete,
		fmt.Sprintf("/accounts/%s/cfd_tunnel/%s?cascade=true", c.accountID, tunnelID),
		nil,
		nil,
	)
}

func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func getTrimmedEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func loadCloudflareProvisioningConfig() (cloudflareProvisioningConfig, bool, error) {
	config := cloudflareProvisioningConfig{
		apiToken:  getTrimmedEnv(cloudflareAPITokenEnv),
		accountID: getTrimmedEnv(cloudflareAccountEnv),
		zoneID:    getTrimmedEnv(cloudflareZoneIDEnv),
		zoneName:  strings.TrimSuffix(getTrimmedEnv(cloudflareZoneNameEnv), "."),
		hostname:  strings.TrimSuffix(getTrimmedEnv(cloudflareHostnameEnv), "."),
	}
	if config.apiToken == "" && config.accountID == "" && config.zoneID == "" && config.zoneName == "" {
		return cloudflareProvisioningConfig{}, false, nil
	}
	if config.apiToken == "" || config.accountID == "" || config.zoneID == "" || config.zoneName == "" {
		return cloudflareProvisioningConfig{}, false, fmt.Errorf(
			"%s=1 with API provisioning requires %s, %s, %s, and %s",
			liveTestsEnv, cloudflareAPITokenEnv, cloudflareAccountEnv, cloudflareZoneIDEnv, cloudflareZoneNameEnv,
		)
	}
	if config.hostname == "" {
		config.hostname = "sing-cloudflared-test." + config.zoneName
	}
	if !strings.HasSuffix(config.hostname, "."+config.zoneName) && config.hostname != config.zoneName {
		return cloudflareProvisioningConfig{}, false, fmt.Errorf(
			"%s must be within zone %s, got %s",
			cloudflareHostnameEnv, config.zoneName, config.hostname,
		)
	}
	return config, true, nil
}

func setupProvisionedLiveTestEnvironment(config cloudflareProvisioningConfig) (_ *liveTestEnvironment, retErr error) {
	origin, err := newTestOriginServer("127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start live origin server: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = origin.Close()
		}
	}()

	client := newCloudflareAPITestClient(config)
	resources := &cloudflareLiveResources{client: client}
	defer func() {
		if retErr != nil {
			_ = resources.Close()
		}
	}()

	setupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tunnelName := "sing-cloudflared-live-" + uuid.NewString()[:8]
	liveTestLogf("live tests: creating tunnel %s for hostname %s", tunnelName, config.hostname)
	createdTunnel, err := client.createTunnel(setupCtx, tunnelName)
	if err != nil {
		return nil, fmt.Errorf("create Cloudflare tunnel: %w", err)
	}
	resources.tunnelID = createdTunnel.ID
	liveTestLogf("live tests: created tunnel id=%s", createdTunnel.ID)

	token, err := client.getTunnelToken(setupCtx, createdTunnel.ID)
	if err != nil {
		return nil, fmt.Errorf("fetch tunnel token: %w", err)
	}

	hostname := config.hostname
	resources.hostname = hostname

	if err := client.updateTunnelConfiguration(setupCtx, createdTunnel.ID, hostname, origin.baseURL); err != nil {
		return nil, fmt.Errorf("update tunnel configuration: %w", err)
	}
	liveTestLogf("live tests: updated tunnel config hostname=%s origin=%s", hostname, origin.baseURL)

	routeResult, err := client.routeTunnelDNS(setupCtx, createdTunnel.ID, hostname)
	if err != nil {
		return nil, fmt.Errorf("create tunnel DNS route: %w", err)
	}
	liveTestLogf("live tests: ensured DNS route hostname=%s dns_tag=%s change=%s", routeResult.Name, routeResult.DNSTag, routeResult.CNAME)

	return &liveTestEnvironment{
		mode:      liveTestModeProvisioned,
		token:     token,
		baseURL:   "https://" + hostname,
		hostname:  hostname,
		origin:    origin,
		resources: resources,
	}, nil
}

func setupLegacyLiveTestEnvironment() (*liveTestEnvironment, error) {
	token := getTrimmedEnv(legacyTunnelTokenEnv)
	baseURL := strings.TrimRight(getTrimmedEnv(legacyTestURLEnv), "/")
	if token == "" || baseURL == "" {
		return nil, fmt.Errorf(
			"%s=1 requires either API provisioning envs or both %s and %s",
			liveTestsEnv, legacyTunnelTokenEnv, legacyTestURLEnv,
		)
	}

	origin, err := newTestOriginServer(legacyOriginListenAddr)
	if err != nil {
		return nil, fmt.Errorf("start legacy live origin server on %s: %w", legacyOriginListenAddr, err)
	}

	return &liveTestEnvironment{
		mode:     liveTestModeLegacy,
		token:    token,
		baseURL:  baseURL,
		hostname: strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://"),
		origin:   origin,
	}, nil
}

var (
	liveEnvironmentOnce      sync.Once
	sharedLiveEnvironment    *liveTestEnvironment
	sharedLiveEnvironmentErr error

	warmUpOnce sync.Once
	warmUpErr  error
)

func requireLiveTestEnvironment(t *testing.T) *liveTestEnvironment {
	t.Helper()
	if !envEnabled(liveTestsEnv) {
		t.Skipf("set %s=1 to run live integration tests", liveTestsEnv)
	}

	liveEnvironmentOnce.Do(func() {
		config, hasProvisioningConfig, err := loadCloudflareProvisioningConfig()
		if err != nil {
			sharedLiveEnvironmentErr = err
			return
		}
		if hasProvisioningConfig {
			sharedLiveEnvironment, sharedLiveEnvironmentErr = setupProvisionedLiveTestEnvironment(config)
			return
		}
		sharedLiveEnvironment, sharedLiveEnvironmentErr = setupLegacyLiveTestEnvironment()
	})

	if sharedLiveEnvironmentErr != nil {
		t.Fatal(sharedLiveEnvironmentErr)
	}

	warmUpOnce.Do(func() {
		warmUpErr = warmUpTunnel(t, sharedLiveEnvironment)
	})
	if warmUpErr != nil {
		t.Fatal("warm up tunnel: ", warmUpErr)
	}

	return sharedLiveEnvironment
}

func warmUpTunnel(t *testing.T, env *liveTestEnvironment) error {
	t.Helper()
	liveTestLogf("live tests: warming up tunnel via HTTP/2")
	service, err := NewService(ServiceOptions{
		Token:         env.token,
		Protocol:      "http2",
		HAConnections: 1,
		Handler:       &testHandler{},
	})
	if err != nil {
		return err
	}
	defer service.Close()
	err = service.Start()
	if err != nil {
		return err
	}
	requestURL := strings.TrimRight(env.baseURL, "/") + "/ping"
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		resp, err := client.Get(requestURL)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == `{"ok":true}` {
				liveTestLogf("live tests: tunnel warm-up complete")
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("tunnel warm-up timed out after 4m at %s", requestURL)
}

func waitForTunnel(t *testing.T, testURL string, timeout time.Duration) {
	t.Helper()
	parsedURL, err := url.Parse(testURL)
	if err != nil {
		t.Fatalf("parse test url %q: %v", testURL, err)
	}
	requestURL := strings.TrimRight(testURL, "/") + "/ping"
	host := parsedURL.Hostname()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	var lastStatus int
	var lastBody string
	var lastLookupError string
	var lastResolvedAddrs string
	lastReport := time.Time{}
	attempt := 0
	t.Logf("waiting for tunnel readiness at %s", requestURL)
	for time.Now().Before(deadline) {
		attempt++
		lookupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, lookupErr := net.DefaultResolver.LookupHost(lookupCtx, host)
		cancel()
		if lookupErr != nil {
			lastLookupError = lookupErr.Error()
			lastResolvedAddrs = ""
		} else {
			lastLookupError = ""
			lastResolvedAddrs = strings.Join(addrs, ",")
		}

		resp, err := client.Get(requestURL)
		if err != nil {
			lastErr = err
			reportLiveWaitState(t, &lastReport, attempt, requestURL, lastLookupError, lastResolvedAddrs, lastStatus, lastBody, lastErr)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = string(body)
		if readErr != nil {
			lastErr = readErr
			reportLiveWaitState(t, &lastReport, attempt, requestURL, lastLookupError, lastResolvedAddrs, lastStatus, lastBody, lastErr)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode == http.StatusOK && lastBody == `{"ok":true}` {
			t.Logf("tunnel ready after %d attempts: %s", attempt, requestURL)
			return
		}
		reportLiveWaitState(t, &lastReport, attempt, requestURL, lastLookupError, lastResolvedAddrs, lastStatus, lastBody, nil)
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf(
		"tunnel not ready after %s for %s (dnsErr=%q, resolved=%q, lastErr=%v, lastStatus=%d, lastBody=%q)",
		timeout, requestURL, lastLookupError, lastResolvedAddrs, lastErr, lastStatus, lastBody,
	)
}

func reportLiveWaitState(t *testing.T, lastReport *time.Time, attempt int, requestURL string, lookupError string, resolvedAddrs string, status int, body string, requestErr error) {
	t.Helper()
	if !testing.Verbose() && !envEnabled(liveTestDebugEnv) {
		return
	}
	now := time.Now()
	if !lastReport.IsZero() && now.Sub(*lastReport) < 5*time.Second {
		return
	}
	*lastReport = now
	t.Logf(
		"waiting for tunnel attempt=%d url=%s dnsErr=%q resolved=%q status=%d body=%q err=%v",
		attempt, requestURL, lookupError, resolvedAddrs, status, body, requestErr,
	)
}

func liveTestLogf(format string, args ...any) {
	if !testing.Verbose() && !envEnabled(liveTestDebugEnv) {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func TestMain(m *testing.M) {
	exitCode := m.Run()

	if sharedLiveEnvironment != nil {
		if err := sharedLiveEnvironment.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to clean up live test environment: %v\n", err)
			if sharedLiveEnvironment.resources != nil {
				fmt.Fprintf(os.Stderr, "tunnel_id=%s hostname=%s\n", sharedLiveEnvironment.resources.tunnelID, sharedLiveEnvironment.resources.hostname)
			}
		}
	}

	os.Exit(exitCode)
}
