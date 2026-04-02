package cloudflared

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	N "github.com/sagernet/sing/common/network"
)

type accessTokenClaims struct {
	jwt.Claims
}

func TestAccessIssuerURL(t *testing.T) {
	t.Parallel()

	if got := accessIssuerURL("team", "fed"); got != "https://team.fed.cloudflareaccess.com" {
		t.Fatalf("unexpected fed issuer %q", got)
	}
	if got := accessIssuerURL("team", "FiPs"); got != "https://team.fed.cloudflareaccess.com" {
		t.Fatalf("unexpected fips issuer %q", got)
	}
	if got := accessIssuerURL("team", ""); got != "https://team.cloudflareaccess.com" {
		t.Fatalf("unexpected default issuer %q", got)
	}
}

func TestOIDCAccessValidatorValidate(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now()
	issuer := accessIssuerURL("team", "")
	keySet := oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}}
	verifier := oidc.NewVerifier(issuer, &keySet, &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: []string{string(jose.ES256)},
	})
	validator := &oidcAccessValidator{
		verifier: verifier,
		audTags:  []string{"aud-1"},
	}

	request := httptest.NewRequest("GET", "https://example.com", nil)
	if err := validator.Validate(context.Background(), request); err == nil {
		t.Fatal("expected missing JWT assertion error")
	}

	token := signAccessTokenForTest(t, accessTokenClaims{
		Claims: jwt.Claims{
			Issuer:   issuer,
			Subject:  "subject",
			Audience: []string{"aud-1"},
			Expiry:   jwt.NewNumericDate(issued.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(issued),
		},
	}, key)
	request.Header.Set(accessJWTAssertionHeader, token)
	if err := validator.Validate(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	mismatched := signAccessTokenForTest(t, accessTokenClaims{
		Claims: jwt.Claims{
			Issuer:   issuer,
			Subject:  "subject",
			Audience: []string{"aud-2"},
			Expiry:   jwt.NewNumericDate(issued.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(issued),
		},
	}, key)
	request.Header.Set(accessJWTAssertionHeader, mismatched)
	if err := validator.Validate(context.Background(), request); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestAccessValidatorCacheReusesConstructedValidator(t *testing.T) {
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()

	var buildCount int
	expected := &fakeAccessValidator{}
	newAccessValidator = func(access config.AccessConfig, dialer N.Dialer) (accessValidator, error) {
		buildCount++
		return expected, nil
	}

	cache := &accessValidatorCache{values: make(map[string]accessValidator)}
	config := config.AccessConfig{Required: true, TeamName: "team", AudTag: []string{"aud"}}
	first, err := cache.Get(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Get(config)
	if err != nil {
		t.Fatal(err)
	}
	if buildCount != 1 {
		t.Fatalf("expected one validator build, got %d", buildCount)
	}
	if first != second || first != expected {
		t.Fatalf("expected validator reuse, got %p and %p", first, second)
	}
}

func signAccessTokenForTest(t *testing.T, claims accessTokenClaims, key *ecdsa.PrivateKey) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signature.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
