package sources

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	pb "github.com/marinoandrea/hoppipolla/pkg/proto/nip_proxy/v1"
)

const defaultDataDir = "/var/lib/hoppipolla/data"

type LocalNipSourceConfig struct {
	// Directory containing the metadata entry files.
	// Defaults to defaultDataDir when empty.
	Path string
}

// Local metadata source for mocks and manually recorded data
type LocalNipSource struct {
	config   LocalNipSourceConfig
	metadata *Metadata
}

func NewLocalNipSource(cfg LocalNipSourceConfig) *LocalNipSource {
	if cfg.Path == "" {
		cfg.Path = defaultDataDir
	}
	return &LocalNipSource{config: cfg}
}

func (s *LocalNipSource) Init(ctx context.Context) error {
	entries, err := os.ReadDir(s.config.Path)
	if err != nil {
		return err
	}

	metadatas := make([]*Metadata, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// #nosec G304 -- path comes from operator config, not request input
		f, err := os.Open(filepath.Join(s.config.Path, entry.Name()))
		if err != nil {
			return err
		}

		metadata, err := parseMetadata(f)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}

		metadatas = append(metadatas, metadata)
	}

	s.metadata = MergeMetadata(metadatas)

	return nil
}

func parseMetadata(r io.Reader) (*Metadata, error) {
	var metadata Metadata
	if err := json.NewDecoder(r).Decode(&metadata); err != nil {
		return nil, err
	}
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (s LocalNipSource) Close(ctx context.Context) error {
	return nil
}

func (s LocalNipSource) GetMetadata(ctx context.Context, req *pb.GetMetadataRequest) (*Metadata, error) {
	return s.metadata, nil
}
