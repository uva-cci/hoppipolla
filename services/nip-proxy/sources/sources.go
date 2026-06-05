package sources

import (
	"context"
	"fmt"
	"time"

	pb "github.com/marinoandrea/hoppipolla/pkg/proto/nip_proxy/v1"
)

type Link struct {
	AsA string `json:"as_a"`
	IfA string `json:"if_a"`
	AsB string `json:"as_b"`
	IfB string `json:"if_b"`
}

type MetadataRequest struct {
	Src      string  `json:"src"`
	Dst      string  `json:"dst"`
	Topology []*Link `json:"topology"`
}

type LinkMetadata struct {
	Name        string     `json:"name"`
	Link        Link       `json:"link"`
	ValueBool   *bool      `json:"value_bool"`
	ValueInt32  *int32     `json:"value_int32"`
	ValueString *string    `json:"value_string"`
	CollectedAt *time.Time `json:"collected_at"`
}

type NodeMetadata struct {
	Name        string     `json:"name"`
	Node        string     `json:"node"`
	ValueBool   *bool      `json:"value_bool"`
	ValueInt32  *int32     `json:"value_int32"`
	ValueString *string    `json:"value_string"`
	CollectedAt *time.Time `json:"collected_at"`
}

type Metadata struct {
	LinkInfo []LinkMetadata `json:"link_info"`
	NodeInfo []NodeMetadata `json:"node_info"`
}

// Checks that every entry carries exactly one value so that consumers
// (e.g. the policy manager reasoner) never receive ambiguous or empty
// metadata.
func (m *Metadata) Validate() error {
	for _, info := range m.LinkInfo {
		if countValues(info.ValueBool, info.ValueInt32, info.ValueString) != 1 {
			return fmt.Errorf(
				"link metadata %q (%s#%s -> %s#%s): exactly one of value_bool, value_int32, value_string must be set",
				info.Name, info.Link.AsA, info.Link.IfA, info.Link.AsB, info.Link.IfB)
		}
	}
	for _, info := range m.NodeInfo {
		if countValues(info.ValueBool, info.ValueInt32, info.ValueString) != 1 {
			return fmt.Errorf(
				"node metadata %q (%s): exactly one of value_bool, value_int32, value_string must be set",
				info.Name, info.Node)
		}
	}
	return nil
}

func countValues(b *bool, i *int32, s *string) int {
	count := 0
	if b != nil {
		count++
	}
	if i != nil {
		count++
	}
	if s != nil {
		count++
	}
	return count
}

// Represents a Network Information Plane (NIP) data source.
// It is an external service which provides network metadata based on
// a topology and optionally a source and destination node for path search.
type NipSource interface {
	GetMetadata(ctx context.Context, req *pb.GetMetadataRequest) (*Metadata, error)
	Init(ctx context.Context) error
	Close(ctx context.Context) error
}

func MergeMetadata(ress []*Metadata) *Metadata {
	var out Metadata
	for _, res := range ress {
		out.NodeInfo = append(out.NodeInfo, res.NodeInfo...)
		out.LinkInfo = append(out.LinkInfo, res.LinkInfo...)
	}
	return &out
}
