package sources

import (
	"reflect"
	"testing"
)

func TestMergeMetadata(t *testing.T) {
	tests := []struct {
		name string
		in   []*Metadata
		want *Metadata
	}{
		{
			name: "empty input",
			in:   []*Metadata{},
			want: &Metadata{},
		},
		{
			name: "single element",
			in: []*Metadata{
				{
					NodeInfo: []NodeMetadata{
						{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
					},
				},
			},
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
				},
			},
		},
		{
			name: "multiple elements preserve order",
			in: []*Metadata{
				{
					NodeInfo: []NodeMetadata{
						{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
					},
				},
				{
					NodeInfo: []NodeMetadata{
						{Node: "19-ffaa:0:1309", Name: "avg_psf", ValueInt32: ptr(int32(10))},
					},
					LinkInfo: []LinkMetadata{
						{
							Name:      "encrypted",
							Link:      Link{AsA: "17-ffaa:0:1101", IfA: "1", AsB: "19-ffaa:0:1309", IfB: "2"},
							ValueBool: ptr(true),
						},
					},
				},
			},
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
					{Node: "19-ffaa:0:1309", Name: "avg_psf", ValueInt32: ptr(int32(10))},
				},
				LinkInfo: []LinkMetadata{
					{
						Name:      "encrypted",
						Link:      Link{AsA: "17-ffaa:0:1101", IfA: "1", AsB: "19-ffaa:0:1309", IfB: "2"},
						ValueBool: ptr(true),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeMetadata(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MergeMetadata() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
