package main

import (
	"testing"
	"time"

	"github.com/marinoandrea/hoppipolla/services/nip-proxy/sources"
)

func ptr[T any](v T) *T { return &v }

func TestFromNodeMetadataToPBCollectedAt(t *testing.T) {
	collectedAt := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

	withTimestamp := FromNodeMetadataToPB(sources.NodeMetadata{
		Name:        "operates",
		Node:        "17-ffaa:0:1101",
		ValueString: ptr("CH"),
		CollectedAt: &collectedAt,
	})
	if withTimestamp.CollectedAt == nil {
		t.Fatal("expected CollectedAt to be set")
	}
	if got := withTimestamp.CollectedAt.AsTime(); !got.Equal(collectedAt) {
		t.Errorf("CollectedAt = %v, want %v", got, collectedAt)
	}

	withoutTimestamp := FromNodeMetadataToPB(sources.NodeMetadata{
		Name:        "operates",
		Node:        "17-ffaa:0:1101",
		ValueString: ptr("CH"),
	})
	if withoutTimestamp.CollectedAt != nil {
		t.Errorf("expected CollectedAt to be nil, got %v", withoutTimestamp.CollectedAt)
	}
}

func TestFromLinkMetadataToPBCollectedAt(t *testing.T) {
	collectedAt := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

	out := FromLinkMetadataToPB(sources.LinkMetadata{
		Name:        "latency",
		Link:        sources.Link{AsA: "17-ffaa:0:1101", IfA: "1", AsB: "17-ffaa:0:1102", IfB: "2"},
		ValueInt32:  ptr(int32(42)),
		CollectedAt: &collectedAt,
	})
	if out.CollectedAt == nil {
		t.Fatal("expected CollectedAt to be set")
	}
	if got := out.CollectedAt.AsTime(); !got.Equal(collectedAt) {
		t.Errorf("CollectedAt = %v, want %v", got, collectedAt)
	}
}
