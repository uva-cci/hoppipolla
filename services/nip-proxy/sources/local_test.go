package sources

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestParseMetadata(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Metadata
		wantErr bool
	}{
		{
			name: "node metadata with string value",
			input: `{
				"node_info": [
					{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH" },
					{ "node": "17-ffaa:0:1102", "name": "operates", "value_string": "CH" }
				],
				"link_info": []
			}`,
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
					{Node: "17-ffaa:0:1102", Name: "operates", ValueString: ptr("CH")},
				},
				LinkInfo: []LinkMetadata{},
			},
		},
		{
			name:  "node metadata with int32 value",
			input: `{ "node_info": [{ "node": "19-ffaa:0:1309", "name": "avg_psf", "value_int32": 10 }] }`,
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "19-ffaa:0:1309", Name: "avg_psf", ValueInt32: ptr(int32(10))},
				},
			},
		},
		{
			name:  "node metadata with bool value",
			input: `{ "node_info": [{ "node": "17-ffaa:0:1101", "name": "gdpr_compliant", "value_bool": true }] }`,
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "17-ffaa:0:1101", Name: "gdpr_compliant", ValueBool: ptr(true)},
				},
			},
		},
		{
			name: "link metadata with nested link",
			input: `{
				"link_info": [
					{
						"name": "latency_ms",
						"link": { "as_a": "17-ffaa:0:1101", "if_a": "1", "as_b": "17-ffaa:0:1102", "if_b": "2" },
						"value_int32": 42
					}
				]
			}`,
			want: &Metadata{
				LinkInfo: []LinkMetadata{
					{
						Name:       "latency_ms",
						Link:       Link{AsA: "17-ffaa:0:1101", IfA: "1", AsB: "17-ffaa:0:1102", IfB: "2"},
						ValueInt32: ptr(int32(42)),
					},
				},
			},
		},
		{
			name: "mixed node and link metadata",
			input: `{
				"node_info": [
					{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH" }
				],
				"link_info": [
					{
						"name": "encrypted",
						"link": { "as_a": "17-ffaa:0:1101", "if_a": "1", "as_b": "17-ffaa:0:1102", "if_b": "2" },
						"value_bool": false
					}
				]
			}`,
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
				},
				LinkInfo: []LinkMetadata{
					{
						Name:      "encrypted",
						Link:      Link{AsA: "17-ffaa:0:1101", IfA: "1", AsB: "17-ffaa:0:1102", IfB: "2"},
						ValueBool: ptr(false),
					},
				},
			},
		},
		{
			name:  "empty object",
			input: `{}`,
			want:  &Metadata{},
		},
		{
			name:    "invalid json",
			input:   `{ "node_info": [`,
			wantErr: true,
		},
		{
			name:    "string-encoded int32 is rejected",
			input:   `{ "node_info": [{ "node": "19-ffaa:0:1309", "name": "avg_psf", "value_int32": "10" }] }`,
			wantErr: true,
		},
		{
			name:    "node metadata without any value is rejected",
			input:   `{ "node_info": [{ "node": "17-ffaa:0:1101", "name": "operates" }] }`,
			wantErr: true,
		},
		{
			name: "node metadata with multiple values is rejected",
			input: `{ "node_info": [
				{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH", "value_bool": true }
			] }`,
			wantErr: true,
		},
		{
			name: "link metadata without any value is rejected",
			input: `{ "link_info": [
				{ "name": "encrypted", "link": { "as_a": "17-ffaa:0:1101", "if_a": "1", "as_b": "17-ffaa:0:1102", "if_b": "2" } }
			] }`,
			wantErr: true,
		},
		{
			name: "collected_at timestamp round-trips",
			input: `{ "node_info": [
				{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH", "collected_at": "2026-06-05T12:00:00Z" }
			] }`,
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{
						Node:        "17-ffaa:0:1101",
						Name:        "operates",
						ValueString: ptr("CH"),
						CollectedAt: ptr(time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMetadata(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseMetadata() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLocalNipSourceInit(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		want    *Metadata
		wantErr bool
	}{
		{
			name: "single file",
			files: map[string]string{
				"01.json": `{ "node_info": [{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH" }], "link_info": [] }`,
			},
			want: &Metadata{
				NodeInfo: []NodeMetadata{
					{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
				},
			},
		},
		{
			name: "multiple files are merged in lexical order",
			files: map[string]string{
				"01.json": `{ "node_info": [{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH" }] }`,
				"02.json": `{
					"node_info": [{ "node": "19-ffaa:0:1309", "name": "avg_psf", "value_int32": 10 }],
					"link_info": [
						{
							"name": "encrypted",
							"link": { "as_a": "17-ffaa:0:1101", "if_a": "1", "as_b": "19-ffaa:0:1309", "if_b": "2" },
							"value_bool": true
						}
					]
				}`,
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
		{
			name:  "empty directory",
			files: map[string]string{},
			want:  &Metadata{},
		},
		{
			name: "malformed file aborts init",
			files: map[string]string{
				"01.json": `{ "node_info": [{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH" }] }`,
				"02.json": `not json`,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			ctx := context.Background()
			src := NewLocalNipSource(LocalNipSourceConfig{Path: dir})

			err := src.Init(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			got, err := src.GetMetadata(ctx, nil)
			if err != nil {
				t.Fatalf("GetMetadata() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMetadata() = %+v, want %+v", got, tt.want)
			}
		})
	}

	t.Run("nonexistent directory", func(t *testing.T) {
		src := NewLocalNipSource(LocalNipSourceConfig{Path: filepath.Join(t.TempDir(), "missing")})
		if err := src.Init(context.Background()); err == nil {
			t.Fatal("Init() expected error for nonexistent directory, got nil")
		}
	})

	t.Run("subdirectories are skipped", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "nested"), 0o750); err != nil {
			t.Fatal(err)
		}
		content := `{ "node_info": [{ "node": "17-ffaa:0:1101", "name": "operates", "value_string": "CH" }] }`
		if err := os.WriteFile(filepath.Join(dir, "01.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		ctx := context.Background()
		src := NewLocalNipSource(LocalNipSourceConfig{Path: dir})
		if err := src.Init(ctx); err != nil {
			t.Fatalf("Init() error = %v", err)
		}

		got, err := src.GetMetadata(ctx, nil)
		if err != nil {
			t.Fatalf("GetMetadata() error = %v", err)
		}
		want := &Metadata{
			NodeInfo: []NodeMetadata{
				{Node: "17-ffaa:0:1101", Name: "operates", ValueString: ptr("CH")},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetMetadata() = %+v, want %+v", got, want)
		}
	})
}
