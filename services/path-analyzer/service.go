package main

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go-simpler.org/env"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/marinoandrea/hoppipolla/pkg/proto/path_analyzer/v1"
	policypb "github.com/marinoandrea/hoppipolla/pkg/proto/policy_manager/v1"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
)

type config struct {
	Host              string `env:"HOST" default:"0.0.0.0"`
	Port              int    `env:"PORT" default:"27001"`
	SciondAddr        string `env:"SCIOND_ADDR" default:"127.0.0.1:30255"`
	CacheSize         int    `env:"CACHE_SIZE" default:"1000"`
	NPaths            int    `env:"N_PATHS" default:"10"`
	PolicyManagerAddr string `env:"POLICY_MANAGER_ADDR" default:"127.0.0.1:27002"`
}

type server struct {
	pb.UnimplementedPathAnalyzerServer
	config              config
	daemon              *daemon.Service
	conn                daemon.Connector
	cache               *expirable.LRU[addr.IA, []*pb.Path]
	policyManagerConn   *grpc.ClientConn
	policyManagerClient policypb.PolicyManagerClient
}

func newServer(cfg config) server {
	return server{
		config: cfg,
		daemon: &daemon.Service{Address: cfg.SciondAddr},
		cache:  expirable.NewLRU[addr.IA, []*pb.Path](cfg.CacheSize, nil, 0),
	}
}

func (s *server) init(ctx context.Context) error {
	conn, err := grpc.NewClient(s.config.PolicyManagerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	s.policyManagerConn = conn
	s.policyManagerClient = policypb.NewPolicyManagerClient(conn)

	// subscribe to policy manager updates to keep cache consistency
	req := policypb.SubscribePathAnalyzerRequest{BroadcastAddr: fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)}
	_, err = s.policyManagerClient.SubscribePathAnalyzer(context.Background(), &req)
	if err != nil {
		return err
	}

	dconn, err := s.daemon.Connect(ctx)
	if err != nil {
		return err
	}
	s.conn = dconn

	return nil
}

func (s *server) shutdown() error {
	err := s.policyManagerConn.Close()
	return err
}

func (s server) Refresh(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	var res emptypb.Empty
	s.cache.Purge()
	return &res, nil
}

func (s server) GetPaths(ctx context.Context, req *pb.GetPathsRequest) (*pb.GetPathsResponse, error) {
	var res pb.GetPathsResponse

	src, err := s.conn.LocalIA(ctx)
	if err != nil {
		return nil, err
	}

	dst, err := addr.ParseIA(req.Destination)
	if err != nil {
		return nil, err
	}

	// check in-memory caches
	paths, ok := s.cache.Get(dst)
	if ok {
		res.Paths = paths
		return &res, nil
	}

	// retrieve new candidates from sciond
	candidates, err := s.conn.Paths(ctx, dst, src, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		return nil, err
	}
	if len(candidates) > s.config.NPaths {
		candidates = candidates[:s.config.NPaths]
	}
	if len(candidates) == 0 {
		res.Paths = []*pb.Path{}
		return &res, nil
	}

	// hand the policy manager the candidate paths as-is; the solver only
	// selects among them, so every returned path is a real, forwardable
	// SCION path by construction
	minExpiry := int64(math.MaxInt64)
	policyPaths := make([]*policypb.Path, 0, len(candidates))
	for _, path := range candidates {
		minExpiry = min(path.Metadata().Expiry.UnixMilli(), minExpiry)
		idfs := path.Metadata().Interfaces
		links := make([]*policypb.Link, 0, len(idfs)-1)
		for i := 0; i+1 < len(idfs); i++ {
			links = append(links, &policypb.Link{
				AsA: idfs[i].IA.String(),
				IfA: idfs[i].ID.String(),
				AsB: idfs[i+1].IA.String(),
				IfB: idfs[i+1].ID.String()})
		}
		policyPaths = append(policyPaths, &policypb.Path{Links: links})
	}

	policyReq := policypb.FindPathsRequest{
		Src:   src.String(),
		Dst:   dst.String(),
		Paths: policyPaths}
	policyRes, err := s.policyManagerClient.FindPaths(ctx, &policyReq)
	if err != nil {
		return nil, err
	}

	paths = make([]*pb.Path, 0, len(policyRes.Paths))
	for _, path := range policyRes.Paths {
		hops, err := pathToHops(policyReq.Src, policyReq.Dst, path.Links)
		if err != nil {
			log.Warnf("dropping malformed path from policy manager: %v", err)
			continue
		}
		paths = append(paths, &pb.Path{Src: policyReq.Src, Dst: policyReq.Dst, Hops: hops})
	}
	res.Paths = paths

	// cache results and evict them once the underlying paths have expired
	if ttl := time.Duration(minExpiry-time.Now().UnixMilli()) * time.Millisecond; ttl > 0 {
		s.cache.Add(dst, paths)
		time.AfterFunc(ttl, func() {
			s.cache.Remove(dst)
		})
	}

	return &res, nil
}

// Converts the link sequence of a path returned by the policy manager into
// the full interface (hop) sequence. The links are echoed back from the
// candidate we sent, so they are validated rather than reconstructed: they
// must form an interface-contiguous chain from src to dst.
func pathToHops(src, dst string, links []*policypb.Link) ([]*pb.Hop, error) {
	if len(links) == 0 {
		return nil, fmt.Errorf("path contains no links")
	}
	if links[0].AsA != src {
		return nil, fmt.Errorf("chain starts at AS %s instead of source %s", links[0].AsA, src)
	}
	if links[len(links)-1].AsB != dst {
		return nil, fmt.Errorf(
			"chain ends at AS %s instead of destination %s", links[len(links)-1].AsB, dst)
	}

	hops := make([]*pb.Hop, 0, len(links)+1)
	hops = append(hops, &pb.Hop{As: links[0].AsA, If: links[0].IfA})
	for i, link := range links {
		if i > 0 {
			prev := links[i-1]
			if prev.AsB != link.AsA || prev.IfB != link.IfA {
				return nil, fmt.Errorf(
					"chain is not contiguous: link %d ends at %s#%s but link %d starts at %s#%s",
					i-1, prev.AsB, prev.IfB, i, link.AsA, link.IfA)
			}
		}
		hops = append(hops, &pb.Hop{As: link.AsB, If: link.IfB})
	}
	return hops, nil
}

func main() {
	log.SetOutput(os.Stdout)

	var cfg config
	if err := env.Load(&cfg, nil); err != nil {
		log.Fatalf("failed to load env vars: %v", err)
	}
	log.Println("Loaded env variables")

	server := newServer(cfg)
	if err := server.init(context.Background()); err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}
	defer func() {
		if err := server.shutdown(); err != nil {
			log.Errorf("failed to shutdown server: %v", err)
		}
	}()
	log.Println("Initialized service")

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", server.config.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	grpcServer.RegisterService(&pb.PathAnalyzer_ServiceDesc, server)
	log.Printf("server listening at %v\n", lis.Addr())
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
