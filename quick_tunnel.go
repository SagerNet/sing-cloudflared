package cloudflared

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

const (
	quickTunnelService = "https://api.trycloudflare.com/tunnel"
	quickTunnelTimeout = 15 * time.Second
)

type QuickTunnel struct {
	ID         uuid.UUID `json:"id"`
	Hostname   string    `json:"hostname"`
	AccountTag string    `json:"account_tag"`
	Secret     []byte    `json:"secret"`
}

func (t QuickTunnel) Credentials() Credentials {
	return Credentials{
		AccountTag:   t.AccountTag,
		TunnelSecret: t.Secret,
		TunnelID:     t.ID,
	}
}

func RequestQuickTunnel(ctx context.Context, dialer N.Dialer, userAgent string) (QuickTunnel, error) {
	if dialer == nil {
		dialer = N.SystemDialer
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: quickTunnelTimeout,
	}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, quickTunnelService, nil)
	if err != nil {
		return QuickTunnel{}, E.Cause(err, "build quick tunnel request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return QuickTunnel{}, E.Cause(err, "request quick tunnel")
	}
	defer response.Body.Close()
	var result struct {
		Success bool        `json:"success"`
		Result  QuickTunnel `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result)
	if err != nil {
		if response.StatusCode != http.StatusOK {
			return QuickTunnel{}, E.New("request quick tunnel: ", response.Status)
		}
		return QuickTunnel{}, E.Cause(err, "decode quick tunnel")
	}
	if !result.Success || len(result.Errors) > 0 {
		messages := make([]string, 0, len(result.Errors))
		for _, item := range result.Errors {
			messages = append(messages, F.ToString("[", item.Code, "] ", item.Message))
		}
		return QuickTunnel{}, E.New("request quick tunnel: ", response.Status, ": ", strings.Join(messages, "; "))
	}
	if result.Result.ID == uuid.Nil || result.Result.Hostname == "" {
		return QuickTunnel{}, E.New("request quick tunnel: incomplete response")
	}
	return result.Result, nil
}
