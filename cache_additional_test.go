package cloudflared

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	N "github.com/sagernet/sing/common/network"
)

func TestAccessValidatorCacheReturnsExistingValueWhenConcurrentStoreWins(t *testing.T) {
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()

	var buildCount atomic.Int32
	firstBuildStarted := make(chan struct{})
	releaseFirstBuild := make(chan struct{})
	cachedValidator := &fakeAccessValidator{}
	firstBuiltValidator := &fakeAccessValidator{}
	newAccessValidator = func(access AccessConfig, dialer N.Dialer) (accessValidator, error) {
		if buildCount.Add(1) == 1 {
			close(firstBuildStarted)
			<-releaseFirstBuild
			return firstBuiltValidator, nil
		}
		return cachedValidator, nil
	}

	cache := &accessValidatorCache{values: make(map[string]accessValidator)}
	config := AccessConfig{Required: true, TeamName: "team", AudTag: []string{"aud"}}

	firstResultCh := make(chan accessValidator, 1)
	firstErrCh := make(chan error, 1)
	go func() {
		validator, err := cache.Get(config)
		firstResultCh <- validator
		firstErrCh <- err
	}()

	<-firstBuildStarted

	second, err := cache.Get(config)
	if err != nil {
		t.Fatal(err)
	}
	close(releaseFirstBuild)

	first := <-firstResultCh
	if err := <-firstErrCh; err != nil {
		t.Fatal(err)
	}
	if first != cachedValidator || second != cachedValidator {
		t.Fatalf("expected both callers to receive cached validator, got %p and %p", first, second)
	}
}

func TestNewDirectOriginTransportReturnsExistingValueWhenConcurrentStoreWins(t *testing.T) {
	originalBaseLoader := loadOriginCABasePool
	originalProxy := proxyFromEnvironment
	defer func() {
		loadOriginCABasePool = originalBaseLoader
		proxyFromEnvironment = originalProxy
	}()

	var buildCount atomic.Int32
	firstBuildStarted := make(chan struct{})
	releaseFirstBuild := make(chan struct{})
	loadOriginCABasePool = func() (*x509.CertPool, error) {
		if buildCount.Add(1) == 1 {
			close(firstBuildStarted)
			<-releaseFirstBuild
		}
		return x509.NewCertPool(), nil
	}
	proxyFromEnvironment = func(request *http.Request) (*url.URL, error) {
		return nil, nil
	}

	serviceInstance := &Service{
		directTransports: make(map[string]*http.Transport),
	}
	service := ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		BaseURL:  &url.URL{Scheme: "http", Host: "localhost"},
	}

	firstTransportCh := make(chan *http.Transport, 1)
	firstErrCh := make(chan error, 1)
	go func() {
		transport, _, err := serviceInstance.newDirectOriginTransport(service, "example.com")
		firstTransportCh <- transport
		firstErrCh <- err
	}()

	<-firstBuildStarted

	secondTransport, _, err := serviceInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	close(releaseFirstBuild)

	firstTransport := <-firstTransportCh
	if err := <-firstErrCh; err != nil {
		t.Fatal(err)
	}
	if firstTransport != secondTransport {
		t.Fatalf("expected concurrent builders to converge on cached transport")
	}
}
