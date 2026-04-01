package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	cloudflared "github.com/sagernet/sing-cloudflared"
	pkgicmp "github.com/sagernet/sing-cloudflared/pkg/icmp"
	N "github.com/sagernet/sing/common/network"
)

type fakeServiceRunner struct {
	startErr   error
	closeErr   error
	startCalls int
	closeCalls int
}

func (s *fakeServiceRunner) Start() error {
	s.startCalls++
	return s.startErr
}

func (s *fakeServiceRunner) Close() error {
	s.closeCalls++
	return s.closeErr
}

func setupCommandRunTest(t *testing.T) {
	t.Helper()

	originalToken := commandRunFlagToken
	originalHAConnections := commandRunFlagHAConnections
	originalProtocol := commandRunFlagProtocol
	originalPostQuantum := commandRunFlagPostQuantum
	originalEdgeIPVersion := commandRunFlagEdgeIPVersion
	originalDatagramVersion := commandRunFlagDatagramVersion
	originalGracePeriod := commandRunFlagGracePeriod
	originalRegion := commandRunFlagRegion
	originalLogLevel := commandRunFlagLogLevel
	originalNewService := commandRunNewService
	originalNewSignals := commandRunNewSignals
	originalNotifySignals := commandRunNotifySignals
	originalStopSignals := commandRunStopSignals
	originalExit := commandRunExit
	originalAfterStart := commandRunAfterStart
	originalStartCloseMonitor := commandRunStartCloseMonitor

	commandRunFlagToken = ""
	commandRunFlagHAConnections = 0
	commandRunFlagProtocol = ""
	commandRunFlagPostQuantum = false
	commandRunFlagEdgeIPVersion = 0
	commandRunFlagDatagramVersion = ""
	commandRunFlagGracePeriod = 0
	commandRunFlagRegion = ""
	commandRunFlagLogLevel = "info"

	commandRunNewService = originalNewService
	commandRunNewSignals = originalNewSignals
	commandRunNotifySignals = originalNotifySignals
	commandRunStopSignals = originalStopSignals
	commandRunExit = originalExit
	commandRunAfterStart = originalAfterStart
	commandRunStartCloseMonitor = originalStartCloseMonitor

	t.Cleanup(func() {
		commandRunFlagToken = originalToken
		commandRunFlagHAConnections = originalHAConnections
		commandRunFlagProtocol = originalProtocol
		commandRunFlagPostQuantum = originalPostQuantum
		commandRunFlagEdgeIPVersion = originalEdgeIPVersion
		commandRunFlagDatagramVersion = originalDatagramVersion
		commandRunFlagGracePeriod = originalGracePeriod
		commandRunFlagRegion = originalRegion
		commandRunFlagLogLevel = originalLogLevel
		commandRunNewService = originalNewService
		commandRunNewSignals = originalNewSignals
		commandRunNotifySignals = originalNotifySignals
		commandRunStopSignals = originalStopSignals
		commandRunExit = originalExit
		commandRunAfterStart = originalAfterStart
		commandRunStartCloseMonitor = originalStartCloseMonitor
	})

	t.Setenv("CF_TUNNEL_TOKEN", "")
}

func TestRunReturnsMissingTokenError(t *testing.T) {
	setupCommandRunTest(t)

	err := run()
	if err == nil || err.Error() != "missing token: provide --token or set CF_TUNNEL_TOKEN" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestRunRejectsUnknownLogLevel(t *testing.T) {
	setupCommandRunTest(t)

	commandRunFlagToken = "token"
	commandRunFlagLogLevel = "verbose"
	commandRunNewService = func(options cloudflared.ServiceOptions) (serviceRunner, error) {
		t.Fatal("unexpected service creation")
		return nil, nil
	}

	err := run()
	if err == nil || err.Error() != "parse log level: unknown log level: verbose" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestRunBuildsServiceOptionsFromFlagsAndEnv(t *testing.T) {
	setupCommandRunTest(t)

	t.Setenv("CF_TUNNEL_TOKEN", "env-token")
	commandRunFlagToken = "flag-token"
	commandRunFlagHAConnections = 3
	commandRunFlagProtocol = "quic"
	commandRunFlagPostQuantum = true
	commandRunFlagEdgeIPVersion = 6
	commandRunFlagDatagramVersion = "v3"
	commandRunFlagGracePeriod = 12 * time.Second
	commandRunFlagRegion = "sjc"
	commandRunFlagLogLevel = "debug"

	startErr := errors.New("start failed")
	service := &fakeServiceRunner{startErr: startErr}
	var captured cloudflared.ServiceOptions
	commandRunNewService = func(options cloudflared.ServiceOptions) (serviceRunner, error) {
		captured = options
		return service, nil
	}
	commandRunNotifySignals = func(ch chan<- os.Signal, signals ...os.Signal) {}
	commandRunStopSignals = func(ch chan<- os.Signal) {}

	err := run()
	if err == nil || !strings.Contains(err.Error(), "start service: start failed") {
		t.Fatalf("unexpected error %v", err)
	}
	if service.startCalls != 1 {
		t.Fatalf("expected one start call, got %d", service.startCalls)
	}
	if service.closeCalls != 1 {
		t.Fatalf("expected one close on start failure, got %d", service.closeCalls)
	}
	if captured.Token != "flag-token" {
		t.Fatalf("expected flag token to win, got %q", captured.Token)
	}
	if captured.HAConnections != 3 {
		t.Fatalf("unexpected HA connections %d", captured.HAConnections)
	}
	if captured.Protocol != "quic" {
		t.Fatalf("unexpected protocol %q", captured.Protocol)
	}
	if !captured.PostQuantum {
		t.Fatal("expected post-quantum to be enabled")
	}
	if captured.EdgeIPVersion != 6 {
		t.Fatalf("unexpected edge IP version %d", captured.EdgeIPVersion)
	}
	if captured.DatagramVersion != "v3" {
		t.Fatalf("unexpected datagram version %q", captured.DatagramVersion)
	}
	if captured.GracePeriod != 12*time.Second {
		t.Fatalf("unexpected grace period %v", captured.GracePeriod)
	}
	if captured.Region != "sjc" {
		t.Fatalf("unexpected region %q", captured.Region)
	}
	if captured.Logger == nil {
		t.Fatal("expected logger to be configured")
	}
	if captured.ConnectionDialer != N.SystemDialer {
		t.Fatalf("expected system dialer, got %T", captured.ConnectionDialer)
	}
	if _, ok := captured.ICMPHandler.(*pkgicmp.DirectHandler); !ok {
		t.Fatalf("expected direct ICMP handler, got %T", captured.ICMPHandler)
	}
}

func TestRunWaitsForSignalAndClosesService(t *testing.T) {
	setupCommandRunTest(t)

	commandRunFlagToken = "flag-token"
	service := &fakeServiceRunner{}
	signals := make(chan os.Signal, 1)
	started := make(chan struct{})
	stopped := make(chan struct{})
	closeMonitorStarted := make(chan struct{}, 1)
	commandRunNewService = func(options cloudflared.ServiceOptions) (serviceRunner, error) {
		return service, nil
	}
	commandRunNewSignals = func() chan os.Signal {
		return signals
	}
	commandRunNotifySignals = func(ch chan<- os.Signal, sigs ...os.Signal) {}
	commandRunStopSignals = func(ch chan<- os.Signal) {
		close(stopped)
	}
	commandRunAfterStart = func() {
		close(started)
	}
	commandRunStartCloseMonitor = func(ctx context.Context) {
		closeMonitorStarted <- struct{}{}
	}
	commandRunExit = func(code int) {
		t.Fatalf("unexpected exit with code %d", code)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- run()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run to start")
	}

	signals <- syscall.SIGTERM

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected run error %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run to stop")
	}

	if service.startCalls != 1 {
		t.Fatalf("expected one start call, got %d", service.startCalls)
	}
	if service.closeCalls != 1 {
		t.Fatalf("expected one close call, got %d", service.closeCalls)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("expected signal handler to stop notifications")
	}
	select {
	case <-closeMonitorStarted:
	default:
		t.Fatal("expected close monitor to start")
	}
}
