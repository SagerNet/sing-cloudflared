package cloudflared

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/coreos/go-oidc/v3/oidc"
)

const accessJWTAssertionHeader = "Cf-Access-Jwt-Assertion"

var newAccessValidator = func(access AccessConfig, dialer N.Dialer) (accessValidator, error) {
	issuerURL := accessIssuerURL(access.TeamName, access.Environment)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
		},
	}
	keySet := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), issuerURL+"/cdn-cgi/access/certs")
	verifier := oidc.NewVerifier(issuerURL, keySet, &oidc.Config{
		SkipClientIDCheck: true,
	})
	return &oidcAccessValidator{
		verifier: verifier,
		audTags:  append([]string(nil), access.AudTag...),
	}, nil
}

type accessValidator interface {
	Validate(ctx context.Context, request *http.Request) error
}

type oidcAccessValidator struct {
	verifier *oidc.IDTokenVerifier
	audTags  []string
}

func (v *oidcAccessValidator) Validate(ctx context.Context, request *http.Request) error {
	accessJWT := request.Header.Get(accessJWTAssertionHeader)
	if accessJWT == "" {
		return E.New("missing access jwt assertion")
	}
	token, err := v.verifier.Verify(ctx, accessJWT)
	if err != nil {
		return err
	}
	if accessTokenAudienceAllowed(token.Audience, v.audTags) {
		return nil
	}
	return E.New("access token audience does not match configured aud_tag")
}

func accessTokenAudienceAllowed(tokenAudience []string, configuredAudTags []string) bool {
	for _, tokenAudTag := range tokenAudience {
		for _, configuredAudTag := range configuredAudTags {
			if configuredAudTag == tokenAudTag {
				return true
			}
		}
	}
	return false
}

func accessIssuerURL(teamName string, environment string) string {
	if strings.EqualFold(environment, "fed") || strings.EqualFold(environment, "fips") {
		return fmt.Sprintf("https://%s.fed.cloudflareaccess.com", teamName)
	}
	return fmt.Sprintf("https://%s.cloudflareaccess.com", teamName)
}

func validateAccessConfiguration(access AccessConfig) error {
	if !access.Required {
		return nil
	}
	if access.TeamName == "" && len(access.AudTag) > 0 {
		return E.New("access.team_name cannot be blank when access.aud_tag is present")
	}
	return nil
}

func accessValidatorKey(access AccessConfig) string {
	return access.TeamName + "|" + access.Environment + "|" + strings.Join(access.AudTag, ",")
}

type accessValidatorCache struct {
	access sync.RWMutex
	values map[string]accessValidator
	dialer N.Dialer
}

func (c *accessValidatorCache) Get(accessConfig AccessConfig) (accessValidator, error) {
	key := accessValidatorKey(accessConfig)
	c.access.RLock()
	validator, loaded := c.values[key]
	c.access.RUnlock()
	if loaded {
		return validator, nil
	}

	validator, err := newAccessValidator(accessConfig, c.dialer)
	if err != nil {
		return nil, err
	}
	c.access.Lock()
	c.values[key] = validator
	c.access.Unlock()
	return validator, nil
}
