package cloudflared

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/config"
	"github.com/sagernet/sing-cloudflared/internal/datagram"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-cloudflared/internal/transport"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

func testToken(t *testing.T) string {
	t.Helper()
	tunnelID := uuid.New()
	secret := []byte("test-secret-32-bytes-long-xxxxx")
	tokenJSON := `{"a":"test-account","t":"` + tunnelID.String() + `","s":"` + base64.StdEncoding.EncodeToString(secret) + `"}`
	return base64.StdEncoding.EncodeToString([]byte(tokenJSON))
}

func newTestService(t *testing.T, token string, testProtocol string, haConnections int) *Service {
	t.Helper()
	credentials, err := parseToken(token)
	if err != nil {
		t.Fatal("parse token: ", err)
	}

	configManager, err := config.NewConfigManager()
	if err != nil {
		t.Fatal("create config manager: ", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serviceInstance := &Service{
		ctx:               ctx,
		cancel:            cancel,
		connectionDialer:  N.SystemDialer,
		logger:            logger.NOP(),
		credentials:       credentials,
		connectorID:       uuid.New(),
		haConnections:     haConnections,
		protocol:          testProtocol,
		edgeIPVersion:     0,
		datagramVersion:   "",
		featureSelector:   transport.NewFeatureSelector(ctx, credentials.AccountTag, ""),
		gracePeriod:       5 * time.Second,
		configManager:     configManager,
		flowLimiter:       &datagram.FlowLimiter{},
		datagramV2Muxers:  make(map[protocol.DatagramSender]*datagram.DatagramV2Muxer),
		datagramV3Muxers:  make(map[protocol.DatagramSender]*datagram.DatagramV3Muxer),
		datagramV3Manager: datagram.NewDatagramV3SessionManager(),
		connectedIndices:  make(map[uint8]struct{}),
		connectedNotify:   make(chan uint8, haConnections),
		controlDialer:     N.SystemDialer,
		tunnelDialer:      N.SystemDialer,
		accessCache:       &accessValidatorCache{values: make(map[string]accessValidator), dialer: N.SystemDialer},
		connectionStates:  make([]connectionState, haConnections),
		directTransports:  make(map[string]*http.Transport),
	}

	t.Cleanup(func() {
		cancel()
		serviceInstance.Close()
	})
	return serviceInstance
}
