package main

import (
	"context"
	"log"
	"os"

	papb "github.com/marinoandrea/hoppipolla/pkg/proto/path_analyzer/v1"
	pmpb "github.com/marinoandrea/hoppipolla/pkg/proto/policy_manager/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

var policyA string
var policyB string
var metaPolicy string

var results [2]*papb.GetPathsResponse

var paClient papb.PathAnalyzerClient
var pmClient pmpb.PolicyManagerClient

func main() {
	setup()
	clean()
	execute()
	clean()
	log.Println(results)
}

func execute() {
	paReq := papb.GetPathsRequest{Destination: "16-ffaa:0:1002"}
	pmReqA := pmpb.CreatePolicyRequest{Source: policyA}
	pmReqB := pmpb.CreatePolicyRequest{Source: policyB}
	pmReqMeta := pmpb.SetMetaPolicyRequest{Source: metaPolicy}

	// publish policy A
	_, err := pmClient.CreatePolicy(context.TODO(), &pmReqA)
	if err != nil {
		log.Fatalln(err)
	}
	// publish policy B
	_, err = pmClient.CreatePolicy(context.TODO(), &pmReqB)
	if err != nil {
		log.Fatalln(err)
	}

	// retrieve valid paths for destination
	paRes1, err := paClient.GetPaths(context.TODO(), &paReq)
	if err != nil {
		log.Println(err)
	}
	results[0] = paRes1

	// publish meta-policy
	_, err = pmClient.SetMetaPolicy(context.TODO(), &pmReqMeta)
	if err != nil {
		log.Fatalln(err)
	}

	// retrieve valid paths for destination
	paRes2, err := paClient.GetPaths(context.TODO(), &paReq)
	if err != nil {
		log.Fatalln(err)
	}
	results[1] = paRes2
}

func setup() {
	// load policy A
	f, err := os.Open("./policy-a.lp")
	if err != nil {
		log.Fatalln(err)
	}

	info, err := f.Stat()
	if err != nil {
		log.Fatalln(err)
	}

	buf := make([]byte, info.Size())

	_, err = f.Read(buf)
	if err != nil {
		log.Fatalln(err)
	}

	policyA = string(buf)
	_ = f.Close()

	// load policy B
	f, err = os.Open("./policy-b.lp")
	if err != nil {
		log.Fatalln(err)
	}

	info, err = f.Stat()
	if err != nil {
		log.Fatalln(err)
	}

	buf = make([]byte, info.Size())

	_, err = f.Read(buf)
	if err != nil {
		log.Fatalln(err)
	}

	policyB = string(buf)
	_ = f.Close()

	// load meta-policy
	f, err = os.Open("./meta-policy.lp")
	if err != nil {
		log.Fatalln(err)
	}

	info, err = f.Stat()
	if err != nil {
		log.Fatalln(err)
	}

	buf = make([]byte, info.Size())

	_, err = f.Read(buf)
	if err != nil {
		log.Fatalln(err)
	}

	metaPolicy = string(buf)
	_ = f.Close()

	// initialize connection to path-analyzer service
	paConn, err := grpc.NewClient("127.0.0.1:27001", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln(err)
	}
	paClient = papb.NewPathAnalyzerClient(paConn)

	// initialize connection to policy-manager service
	pmConn, err := grpc.NewClient("127.0.0.1:27002", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln(err)
	}
	pmClient = pmpb.NewPolicyManagerClient(pmConn)
}

func clean() {
	if _, err := pmClient.ResetPolicies(context.TODO(), &emptypb.Empty{}); err != nil {
		log.Println("ERROR: failed to reset policies:", err)
	}
	if _, err := paClient.Refresh(context.TODO(), &emptypb.Empty{}); err != nil {
		log.Println("ERROR: failed to refresh paths:", err)
	}
}
