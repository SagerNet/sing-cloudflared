package cloudflared

import (
	"context"
	"hash/fnv"
	"testing"
)

func TestResolveRemoteDatagramVersionRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := resolveRemoteDatagramVersion("account", []byte("{"))
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestAccountEnabledThresholdBoundary(t *testing.T) {
	t.Parallel()

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte("boundary-account"))
	threshold := hasher.Sum32() % 100

	if accountEnabled("boundary-account", threshold) {
		t.Fatal("expected threshold percentage to remain disabled")
	}
	if !accountEnabled("boundary-account", threshold+1) {
		t.Fatal("expected threshold+1 percentage to enable account")
	}
}

func TestFeatureSelectorSnapshotReturnsIndependentFeatureSlice(t *testing.T) {
	t.Parallel()

	selector := newFeatureSelector(context.Background(), "account", defaultDatagramVersion)
	_, first := selector.Snapshot()
	first[0] = "mutated"

	_, second := selector.Snapshot()
	if second[0] == "mutated" {
		t.Fatal("expected snapshot to return a copy of default features")
	}
}
