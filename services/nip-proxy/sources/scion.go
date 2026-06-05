package sources

import (
	"context"
	"log"
	"math"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	pb "github.com/marinoandrea/hoppipolla/pkg/proto/nip_proxy/v1"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"googlemaps.github.io/maps"
)

type ScionNipSourceConfig struct {
	SciondAddress     string
	GoogleMapsApiKey  string
	CacheSize         int
	EnableGeolocation bool
}

type ScionCacheKey struct {
	src addr.IA
	dst addr.IA
}

type ScionCacheValue struct {
	request  *pb.GetMetadataRequest
	metadata *Metadata
}

// Metadata source leveraging SCION beacon metadata and
// optional Google reverse geolocation
type ScionNipSource struct {
	config             ScionNipSourceConfig
	daemon             *daemon.Service
	conn               daemon.Connector
	cache              *expirable.LRU[ScionCacheKey, ScionCacheValue]
	cacheRefreshTicker *time.Ticker
	cacheRefreshChan   chan bool
	googleMapsClient   *maps.Client
}

func NewScionNipSource(cfg ScionNipSourceConfig) *ScionNipSource {
	return &ScionNipSource{
		config:             cfg,
		daemon:             &daemon.Service{Address: cfg.SciondAddress},
		cache:              expirable.NewLRU[ScionCacheKey, ScionCacheValue](cfg.CacheSize, nil, 0),
		cacheRefreshTicker: time.NewTicker(1 * time.Minute), // SCION default TTL for paths
		cacheRefreshChan:   make(chan bool),
	}
}

func (s *ScionNipSource) Init(ctx context.Context) error {
	dconn, err := s.daemon.Connect(ctx)
	if err != nil {
		return err
	}
	s.conn = dconn
	log.Printf("Connected to SCION daemon at '%s'", s.config.SciondAddress)

	if s.config.EnableGeolocation {
		gclient, err := maps.NewClient(maps.WithAPIKey(s.config.GoogleMapsApiKey))
		if err != nil {
			return err
		}
		s.googleMapsClient = gclient
		log.Println("Initialized Google Maps client")
	}

	go func() {
		for {
			select {
			case <-s.cacheRefreshChan:
				return
			case <-s.cacheRefreshTicker.C:
				// update cache
				// TODO(andrea): parallelize
				for _, key := range s.cache.Keys() {
					value, _ := s.cache.Get(key)
					metadata, err := s.GetMetadata(ctx, value.request)
					if err != nil {
						log.Println("ERROR: ", err)
						continue
					}
					s.cache.Add(key, ScionCacheValue{
						request:  value.request,
						metadata: metadata})
				}
			}
		}
	}()
	log.Println("Started monitoring daemon")

	return nil
}

func (s ScionNipSource) Close(ctx context.Context) error {
	s.cacheRefreshTicker.Stop()
	s.cacheRefreshChan <- true
	return s.conn.Close()
}

func (s ScionNipSource) GetMetadata(ctx context.Context, req *pb.GetMetadataRequest) (*Metadata, error) {
	var out []*Metadata

	src, err := addr.ParseIA(req.Src)
	if err != nil {
		return nil, err
	}

	dst, err := addr.ParseIA(req.Dst)
	if err != nil {
		return nil, err
	}

	cached, ok := s.cache.Get(ScionCacheKey{src, dst})
	if ok {
		return cached.metadata, nil
	}

	// NOTE(andrea): we are replicating path discovery in the NIP proxy simply
	// because of how the SCION API works, information retrieval is based on paths.
	paths, err := s.conn.Paths(ctx, dst, src, daemon.PathReqFlags{})
	if err != nil {
		return nil, err
	}

	wg := sync.WaitGroup{}
	ch := make(chan Metadata, len(paths))

	for _, path := range paths {
		wg.Add(1)
		go s.getPathMetadata(ctx, path, ch, &wg)
	}

	wg.Wait()
	close(ch)

	for metadata := range ch {
		out = append(out, &metadata)
	}

	return MergeMetadata(out), nil
}

func (s ScionNipSource) getPathMetadata(ctx context.Context, path snet.Path, ch chan Metadata, wg *sync.WaitGroup) {
	var out Metadata

	collectedAt := time.Now()

	for i, current_itf := range path.Metadata().Interfaces {
		if s.config.EnableGeolocation {
			location := path.Metadata().Geo[i]
			geocode, err := s.googleMapsClient.ReverseGeocode(ctx, &maps.GeocodingRequest{
				LatLng: &maps.LatLng{
					Lat: float64(location.Latitude),
					Lng: float64(location.Longitude)}})
			if err != nil {
				log.Println(err)
			}

			if len(geocode) > 0 {
				countries := make([]string, 0, len(geocode[0].AddressComponents))
				for _, addrComp := range geocode[0].AddressComponents {
					for _, addrCompType := range addrComp.Types {
						if addrCompType == "country" {
							countries = append(countries, addrComp.ShortName)
						}
					}
				}
				for _, country := range countries {
					out.NodeInfo = append(out.NodeInfo, NodeMetadata{
						Name:        "operates",
						Node:        current_itf.IA.String(),
						ValueString: &country,
						CollectedAt: &collectedAt,
					})
				}
			}
		}

		if i == len(path.Metadata().Interfaces)-1 {
			break
		}

		next_itf := path.Metadata().Interfaces[i+1]
		link := Link{
			AsA: current_itf.IA.String(),
			IfA: current_itf.ID.String(),
			AsB: next_itf.IA.String(),
			IfB: next_itf.ID.String(),
		}

		// NOTE: our reasoner only supports 32-bit integers, so we saturate
		// instead of overflowing; this should never trigger with realistic data
		bandwidth := int32(min(path.Metadata().Bandwidth[i], math.MaxInt32))                        // #nosec G115 -- clamped to int32 range above
		latency := int32(min(max(int64(path.Metadata().Latency[i]), math.MinInt32), math.MaxInt32)) // #nosec G115 -- clamped to int32 range above

		out.LinkInfo = append(out.LinkInfo, LinkMetadata{
			Name:        "bandwidth",
			Link:        link,
			ValueInt32:  &bandwidth,
			CollectedAt: &collectedAt,
		})
		out.LinkInfo = append(out.LinkInfo, LinkMetadata{
			Name:        "latency",
			Link:        link,
			ValueInt32:  &latency,
			CollectedAt: &collectedAt,
		})
	}

	ch <- out
	wg.Done()
}
