package main

import (
	"testing"

	policypb "github.com/marinoandrea/hoppipolla/pkg/proto/policy_manager/v1"
)

const (
	asSrc = "1-ff00:0:110"
	asB   = "1-ff00:0:111"
	asDst = "1-ff00:0:113"
)

// src -1-> (2)B(3) -4-> dst, including the intra-AS traversal of B,
// mirroring how candidates are sent to (and echoed back by) the
// policy manager
func validChain() []*policypb.Link {
	return []*policypb.Link{
		{AsA: asSrc, IfA: "1", AsB: asB, IfB: "2"},
		{AsA: asB, IfA: "2", AsB: asB, IfB: "3"},
		{AsA: asB, IfA: "3", AsB: asDst, IfB: "4"},
	}
}

func TestPathToHops(t *testing.T) {
	t.Run("valid chain yields the full interface sequence", func(t *testing.T) {
		hops, err := pathToHops(asSrc, asDst, validChain())
		if err != nil {
			t.Fatalf("pathToHops() error = %v", err)
		}
		want := []struct{ as, itf string }{
			{asSrc, "1"}, {asB, "2"}, {asB, "3"}, {asDst, "4"},
		}
		if len(hops) != len(want) {
			t.Fatalf("expected %d hops, got %d", len(want), len(hops))
		}
		for i, hop := range hops {
			if hop.As != want[i].as || hop.If != want[i].itf {
				t.Errorf("hop %d = %s#%s, want %s#%s", i, hop.As, hop.If, want[i].as, want[i].itf)
			}
		}
	})

	tests := []struct {
		name  string
		links []*policypb.Link
	}{
		{name: "empty links", links: nil},
		{
			name: "chain not starting at source",
			links: []*policypb.Link{
				{AsA: asB, IfA: "3", AsB: asDst, IfB: "4"},
			},
		},
		{
			name: "chain not ending at destination",
			links: []*policypb.Link{
				{AsA: asSrc, IfA: "1", AsB: asB, IfB: "2"},
			},
		},
		{
			name: "chain with AS gap",
			links: []*policypb.Link{
				{AsA: asSrc, IfA: "1", AsB: asB, IfB: "2"},
				{AsA: asDst, IfA: "9", AsB: asDst, IfB: "4"},
			},
		},
		{
			name: "chain with interface mismatch",
			links: []*policypb.Link{
				{AsA: asSrc, IfA: "1", AsB: asB, IfB: "2"},
				// enters B on interface 2 but continues from interface 9
				{AsA: asB, IfA: "9", AsB: asDst, IfB: "4"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pathToHops(asSrc, asDst, tt.links); err == nil {
				t.Fatal("pathToHops() expected error, got nil")
			}
		})
	}
}
