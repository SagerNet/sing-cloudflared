package cloudflared

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

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
		ctx:               ctx,
		cancel:            cancel,
		handler:           &testHandler{},
		logger:            logger.NOP(),
		credentials:       credentials,
		connectorID:       uuid.New(),
		haConnections:     haConnections,
		protocol:          protocol,
		edgeIPVersion:     0,
		datagramVersion:   "",
		featureSelector:   newFeatureSelector(ctx, credentials.AccountTag, ""),
		gracePeriod:       5 * time.Second,
		configManager:     configManager,
		datagramV2Muxers:  make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers:  make(map[DatagramSender]*DatagramV3Muxer),
		datagramV3Manager: NewDatagramV3SessionManager(),
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
