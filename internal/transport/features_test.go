package transport

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/control"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
)

func TestFeatureSelectorConfiguredWins(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	selector := NewFeatureSelector(ctx, "account", "v3")
	version, features := selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected configured version to win, got %s", version)
	}
	if !slices.Contains(features, "support_datagram_v3_2") {
		t.Fatalf("expected v3 feature list, got %#v", features)
	}
}

func TestFeatureSelectorInitialRemoteSelection(t *testing.T) {
	t.Parallel()
	selector := &FeatureSelector{
		accountTag:             "account",
		lookup:                 func(context.Context) ([]byte, error) { return []byte(`{"dv3_2":100}`), nil },
		currentDatagramVersion: protocol.DefaultDatagramVersion,
	}

	err := selector.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	version, _ := selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected auto-selected v3, got %s", version)
	}
}

func TestFeatureSelectorRefreshUpdatesSnapshot(t *testing.T) {
	t.Parallel()
	record := []byte(`{"dv3_2":0}`)
	selector := &FeatureSelector{
		accountTag:             "account",
		currentDatagramVersion: protocol.DefaultDatagramVersion,
		lookup: func(context.Context) ([]byte, error) {
			return record, nil
		},
	}

	err := selector.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	version, _ := selector.Snapshot()
	if version != protocol.DefaultDatagramVersion {
		t.Fatalf("expected initial v2, got %s", version)
	}

	record = []byte(`{"dv3_2":100}`)
	err = selector.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	version, _ = selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected refreshed v3, got %s", version)
	}
}

func TestFeatureSelectorRefreshFailureKeepsPreviousValue(t *testing.T) {
	t.Parallel()
	selector := &FeatureSelector{
		accountTag:             "account",
		currentDatagramVersion: "v3",
		lookup: func(context.Context) ([]byte, error) {
			return nil, errors.New("lookup failed")
		},
	}

	err := selector.refresh(context.Background())
	if err == nil {
		t.Fatal("expected refresh failure")
	}

	version, _ := selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected previous version to be retained, got %s", version)
	}
}

func TestFeatureSelectorSnapshotReflectsVersionChange(t *testing.T) {
	t.Parallel()
	selector := &FeatureSelector{
		accountTag:             "account",
		currentDatagramVersion: protocol.DefaultDatagramVersion,
	}

	version, features := selector.Snapshot()
	if version != protocol.DefaultDatagramVersion {
		t.Fatalf("expected initial v2, got %s", version)
	}
	if slices.Contains(features, "support_datagram_v3_2") {
		t.Fatalf("unexpected v3 feature list: %#v", features)
	}

	selector.access.Lock()
	selector.currentDatagramVersion = "v3"
	selector.access.Unlock()

	version, features = selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected refreshed v3, got %s", version)
	}
	if !slices.Contains(features, "support_datagram_v3_2") {
		t.Fatalf("expected v3 feature list, got %#v", features)
	}
}

func TestDefaultFeaturesIncludesPostQuantumWhenRequested(t *testing.T) {
	t.Parallel()

	features := control.DefaultFeatures(protocol.DefaultDatagramVersion)
	features = append(features, FeaturePostQuantum)
	if !slices.Contains(features, FeaturePostQuantum) {
		t.Fatalf("expected post-quantum feature, got %#v", features)
	}
}
