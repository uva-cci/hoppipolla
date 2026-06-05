package main

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/marinoandrea/hoppipolla/pkg/proto/nip_proxy/v1"
	"github.com/marinoandrea/hoppipolla/services/nip-proxy/sources"
)

func FromPBToLink(input *pb.Link) *sources.Link {
	return &sources.Link{
		AsA: input.AsA,
		IfA: input.IfA,
		AsB: input.AsB,
		IfB: input.IfB,
	}
}

func FromPBToMetadataRequest(input *pb.GetMetadataRequest) *sources.MetadataRequest {
	topology := make([]*sources.Link, 0)
	for _, pbLink := range input.Topology {
		topology = append(topology, FromPBToLink(pbLink))
	}

	return &sources.MetadataRequest{
		Src:      input.Src,
		Dst:      input.Dst,
		Topology: topology,
	}
}

func FromNodeMetadataToPB(input sources.NodeMetadata) *pb.NodeMetadata {
	return &pb.NodeMetadata{
		Name:        input.Name,
		Node:        input.Node,
		ValueBool:   input.ValueBool,
		ValueInt32:  input.ValueInt32,
		ValueString: input.ValueString,
		CollectedAt: toPBTimestamp(input.CollectedAt),
	}
}

func FromLinkMetadataToPB(input sources.LinkMetadata) *pb.LinkMetadata {
	return &pb.LinkMetadata{
		Name: input.Name,
		Link: &pb.Link{
			AsA: input.Link.AsA,
			IfA: input.Link.IfA,
			AsB: input.Link.AsB,
			IfB: input.Link.IfB,
		},
		ValueBool:   input.ValueBool,
		ValueInt32:  input.ValueInt32,
		ValueString: input.ValueString,
		CollectedAt: toPBTimestamp(input.CollectedAt),
	}
}

func toPBTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}
