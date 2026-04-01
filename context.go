package cloudflared

import (
	"context"
	"math/rand"
	"time"

	"github.com/sagernet/sing/common/random"
)

func init() {
	random.InitializeSeed()
}

type contextIDKey struct{}

type ContextID struct {
	ID        uint32
	CreatedAt time.Time
}

func contextWithNewID(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*contextIDKey)(nil), ContextID{
		ID:        rand.Uint32(),
		CreatedAt: time.Now(),
	})
}

func ContextIDFrom(ctx context.Context) (ContextID, bool) {
	id, loaded := ctx.Value((*contextIDKey)(nil)).(ContextID)
	return id, loaded
}
