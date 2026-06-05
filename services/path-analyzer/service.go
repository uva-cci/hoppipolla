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

	minExpiry := int64(math.MaxInt64)
	links := make([]*policypb.Link, 0)
	for _, path := range candidates[:s.config.NPaths] {
		minExpiry = min(path.Metadata().Expiry.UnixMilli(), minExpiry)
		idfs := path.Metadata().Interfaces
		for i := range len(idfs) {
			if i == len(idfs)-1 {
				break
			}
			idfA := idfs[i]
			idfB := idfs[i+1]
			links = append(links, &policypb.Link{
				AsA: idfA.IA.String(),
				IfA: idfA.ID.String(),
				AsB: idfB.IA.String(),
				IfB: idfB.ID.String()})
		}
	}

	// evict cache once paths have expired
	time.AfterFunc(time.Duration((minExpiry-time.Now().UnixMilli())*time.Hour.Milliseconds()), func() {
		s.cache.Remove(dst)
	})

	policyReq := policypb.FindPathsRequest{
		Src:   src.String(),
		Dst:   dst.String(),
		Links: links}
	policyRes, err := s.policyManagerClient.FindPaths(ctx, &policyReq)
	if err != nil {
		return nil, err
	}

	paths = make([]*pb.Path, 0, len(policyRes.Paths))
	for _, path := range policyRes.Paths {
		paths = append(paths, fromPolicyPBToPathPB(policyReq.Src, policyReq.Dst, path))
	}
	s.cache.Add(dst, paths)
	res.Paths = paths

	return &res, nil
}

// Reconstructs the path in order of visit
func fromPolicyPBToPathPB(src string, dst string, path *policypb.Path) *pb.Path {
	cut := func(i int, xs []*policypb.Link) (*policypb.Link, []*policypb.Link) {
		y := xs[i]
		ys := append(xs[:i], xs[i+1:]...)
		return y, ys
	}

	out := pb.Path{
		Src:  src,
		Dst:  dst,
		Hops: make([]*pb.Hop, 0, len(path.Links)*2),
	}

	currentNode := src
	for {
		found_i := -1
		for i, link := range path.Links {
			if currentNode == out.Src {
				out.Hops = append(out.Hops, &pb.Hop{
					As: link.AsA,
					If: link.IfA,
				})
				out.Hops = append(out.Hops, &pb.Hop{
					As: link.AsB,
					If: link.IfB,
				})
				currentNode = link.AsB
				found_i = i
				break
			} else if link.AsA == currentNode {
				out.Hops = append(out.Hops, &pb.Hop{
					As: link.AsB,
					If: link.IfB,
				})
				currentNode = link.AsB
				found_i = i
				break
			}
		}

		if len(path.Links) == 0 || found_i == -1 {
			break
		}

		cut(found_i, path.Links)
	}

	return &out
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
