package main

import (
	"context"
	"log"

	papb "github.com/marinoandrea/hoppipolla/pkg/proto/path_analyzer/v1"
	pmpb "github.com/marinoandrea/hoppipolla/pkg/proto/policy_manager/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

var results *papb.GetPathsResponse

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

	paRes, err := paClient.GetPaths(context.TODO(), &paReq)
	if err != nil {
		log.Fatalln(err)
	}
	results = paRes
}

func setup() {
	paConn, err := grpc.NewClient("127.0.0.1:27001", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln(err)
	}
	paClient = papb.NewPathAnalyzerClient(paConn)

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
