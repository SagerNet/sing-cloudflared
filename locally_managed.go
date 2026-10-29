package cloudflared

import (
	"context"

	"github.com/sagernet/sing-cloudflared/internal/protocol"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/uuid"
)

type Credentials = protocol.Credentials

type LocallyManagedOptions struct {
	Credentials *Credentials
	Service     string
	Renew       func(ctx context.Context) (Credentials, error)
}

func (s *Service) currentCredentials() protocol.Credentials {
	s.credentialsAccess.Lock()
	defer s.credentialsAccess.Unlock()
	return s.credentials
}

func (s *Service) renewCredentials(previous uuid.UUID) error {
	s.credentialsAccess.Lock()
	defer s.credentialsAccess.Unlock()
	if s.credentials.TunnelID != previous {
		return nil
	}
	credentials, err := s.locallyManaged.Renew(s.ctx)
	if err != nil {
		return E.Cause(err, "renew tunnel credentials")
	}
	s.credentials = credentials
	s.logger.Info("using tunnel ", credentials.TunnelID)
	return nil
}
