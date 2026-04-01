package cloudflared

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	liveCLIBinaryOnce sync.Once
	liveCLIBinaryPath string
	liveCLIBinaryErr  error
	liveCLIBuildLogs  string
)

type liveCLIProcess struct {
	command *exec.Cmd
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	waitCh  chan error

	waitAccess sync.Mutex
	waitLoaded bool
	waitErr    error
}

func buildLiveCLIBinary(t *testing.T) string {
	t.Helper()

	liveCLIBinaryOnce.Do(func() {
		binaryDir, err := os.MkdirTemp("", "sing-cloudflared-live-cli-*")
		if err != nil {
			liveCLIBinaryErr = err
			return
		}
		binaryName := "cloudflared-live"
		if runtime.GOOS == "windows" {
			binaryName += ".exe"
		}
		liveCLIBinaryPath = binaryDir + string(os.PathSeparator) + binaryName

		build := exec.Command("go", "build", "-o", liveCLIBinaryPath, "./cmd/cloudflared")
		build.Dir = "."
		output, err := build.CombinedOutput()
		if err != nil {
			liveCLIBinaryErr = err
			liveCLIBuildLogs = string(output)
		}
	})

	if liveCLIBinaryErr != nil {
		t.Fatalf("build live CLI binary: %v\n%s", liveCLIBinaryErr, liveCLIBuildLogs)
	}
	return liveCLIBinaryPath
}

func startLiveCLIProcess(t *testing.T, env *liveTestEnvironment, args ...string) *liveCLIProcess {
	t.Helper()

	process := &liveCLIProcess{waitCh: make(chan error, 1)}
	commandArgs := append([]string{"run"}, args...)
	process.command = exec.Command(buildLiveCLIBinary(t), commandArgs...)
	process.command.Env = append(os.Environ(), "CF_TUNNEL_TOKEN="+env.token)
	process.command.Stdout = &process.stdout
	process.command.Stderr = &process.stderr

	if err := process.command.Start(); err != nil {
		t.Fatalf("start live CLI process: %v", err)
	}
	go func() {
		process.waitCh <- process.command.Wait()
	}()
	return process
}

func (p *liveCLIProcess) logs() string {
	return "stdout:\n" + p.stdout.String() + "\nstderr:\n" + p.stderr.String()
}

func (p *liveCLIProcess) pollExit() (bool, error) {
	p.waitAccess.Lock()
	if p.waitLoaded {
		err := p.waitErr
		p.waitAccess.Unlock()
		return true, err
	}
	p.waitAccess.Unlock()

	select {
	case err := <-p.waitCh:
		p.waitAccess.Lock()
		p.waitLoaded = true
		p.waitErr = err
		p.waitAccess.Unlock()
		return true, err
	default:
		return false, nil
	}
}

func (p *liveCLIProcess) wait(timeout time.Duration) error {
	if exited, err := p.pollExit(); exited {
		return err
	}

	select {
	case err := <-p.waitCh:
		p.waitAccess.Lock()
		p.waitLoaded = true
		p.waitErr = err
		p.waitAccess.Unlock()
		return err
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}

func (p *liveCLIProcess) terminate(t *testing.T) {
	t.Helper()

	if p.command == nil || p.command.Process == nil {
		return
	}
	if exited, _ := p.pollExit(); exited {
		return
	}

	if runtime.GOOS != "windows" {
		_ = p.command.Process.Signal(syscall.SIGTERM)
		if err := p.wait(5 * time.Second); err == nil {
			return
		}
	}

	_ = p.command.Process.Kill()
	_ = p.wait(5 * time.Second)
}

func waitForLiveCLIReady(t *testing.T, process *liveCLIProcess, baseURL string, timeout time.Duration) {
	t.Helper()

	requestURL := strings.TrimRight(baseURL, "/") + "/ping"
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if exited, err := process.pollExit(); exited {
			t.Fatalf("CLI exited before readiness: %v\n%s", err, process.logs())
		}

		resp, err := client.Get(requestURL)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == `{"ok":true}` {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for CLI readiness at %s\n%s", requestURL, process.logs())
}

func TestLiveCLIRunQUICV2Smoke(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	process := startLiveCLIProcess(t, env,
		"--protocol", "quic",
		"--datagram-version", "v2",
		"--ha-connections", "1",
	)
	defer process.terminate(t)

	waitForLiveCLIReady(t, process, env.baseURL, 2*time.Minute)

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestLiveCLIRunQUICV3Smoke(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	process := startLiveCLIProcess(t, env,
		"--protocol", "quic",
		"--datagram-version", "v3",
		"--ha-connections", "1",
	)
	defer process.terminate(t)

	waitForLiveCLIReady(t, process, env.baseURL, 2*time.Minute)

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestLiveCLIGracefulClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM graceful shutdown timing is only asserted on Unix-like runners")
	}

	env := requireLiveTestEnvironment(t)
	process := startLiveCLIProcess(t, env,
		"--protocol", "quic",
		"--datagram-version", "v2",
		"--ha-connections", "1",
		"--grace-period", "2s",
	)
	defer process.terminate(t)

	waitForLiveCLIReady(t, process, env.baseURL, 2*time.Minute)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(env.HTTPURL("/sse?count=50&interval_ms=200"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	if firstEvent := readNextSSEEvent(t, reader); firstEvent != "1" {
		t.Fatalf("expected first SSE event to be 1, got %q", firstEvent)
	}

	closeStarted := time.Now()
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	eventsAfterClose := 0
	for eventsAfterClose < 3 {
		event, err := readNextSSEEventValue(reader)
		if err != nil {
			break
		}
		if event != "" {
			eventsAfterClose++
		}
	}

	err = process.wait(8 * time.Second)
	if err != nil {
		t.Fatalf("CLI exit: %v\n%s", err, process.logs())
	}

	closeDuration := time.Since(closeStarted)
	if closeDuration < time.Second {
		t.Fatalf("expected graceful shutdown to wait for in-flight stream, got %s", closeDuration)
	}
	if closeDuration > 8*time.Second {
		t.Fatalf("expected graceful shutdown to complete within 8s, got %s", closeDuration)
	}
	if eventsAfterClose == 0 {
		t.Fatal("expected at least one SSE event after SIGTERM")
	}
}
