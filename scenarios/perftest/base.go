package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	papb "github.com/marinoandrea/hoppipolla/pkg/proto/path_analyzer/v1"
	pmpb "github.com/marinoandrea/hoppipolla/pkg/proto/policy_manager/v1"
)

func executeBasePerftest() {
	setupBase()
	cleanBase()
	executeBasePtc1()
	log.Println("Executed PTC1")
	cleanBase()
	executeBasePtc2()
	log.Println("Executed PTC2")
	cleanBase()
	executeBasePtc3()
	log.Println("Executed PTC3")
	cleanBase()
	executeBasePtc4()
	log.Println("Executed PTC4")
	cleanBase()
	executeBasePtc5()
	log.Println("Executed PTC5")
	cleanBase()
	saveBaseResults()
}

func executeBasePtc1() {
	src, err := scionDaemonConn.LocalIA(context.TODO())
	if err != nil {
		log.Fatalln(err)
	}

	dst, err := addr.ParseIA(DST)
	if err != nil {
		log.Fatalln(err)
	}

	for i := range N_RUNS {
		start := time.Now()
		_, err = scionDaemonConn.Paths(context.TODO(), dst, src,
			daemon.PathReqFlags{Refresh: true})
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalln(err)
		}
		results[0][i] = elapsed
	}
}

func executeBasePtc2() {
	paConn, err := grpc.NewClient(ADDR_PATH_ANALYZER, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln(err)
	}
	defer func() { _ = paConn.Close() }()

	paClient := papb.NewPathAnalyzerClient(paConn)
	paReq := papb.GetPathsRequest{Destination: DST}

	for i := range N_RUNS {
		start := time.Now()
		_, err := paClient.GetPaths(context.TODO(), &paReq)
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalln(err)
		}
		_, err = paClient.Refresh(context.TODO(), &emptypb.Empty{})
		if err != nil {
			log.Fatalln(err)
		}
		results[1][i] = elapsed
	}
}

func executeBasePtc3() {
	f, err := os.Open("./deny-non-gdpr/policy.lp")
	if err != nil {
		log.Fatalln(err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		log.Fatalln(err)
	}

	buf := make([]byte, info.Size())

	_, err = f.Read(buf)
	if err != nil {
		log.Fatalln(err)
	}

	pmReq := pmpb.CreatePolicyRequest{Source: string(buf)}

	_, err = pmClient.CreatePolicy(context.TODO(), &pmReq)
	if err != nil {
		log.Fatalln(err)
	}

	paReq := papb.GetPathsRequest{Destination: DST}
	for i := range N_RUNS {
		start := time.Now()
		_, err := paClient.GetPaths(context.TODO(), &paReq)
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalln(err)
		}
		_, err = paClient.Refresh(context.TODO(), &emptypb.Empty{})
		if err != nil {
			log.Fatalln(err)
		}
		results[2][i] = elapsed
	}
}

func executeBasePtc4() {
	f, err := os.Open("./prefer-higher-psf/policy.lp")
	if err != nil {
		log.Fatalln(err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		log.Fatalln(err)
	}

	buf := make([]byte, info.Size())

	_, err = f.Read(buf)
	if err != nil {
		log.Fatalln(err)
	}

	pmReq := pmpb.CreatePolicyRequest{Source: string(buf)}

	_, err = pmClient.CreatePolicy(context.TODO(), &pmReq)
	if err != nil {
		log.Fatalln(err)
	}

	paReq := papb.GetPathsRequest{Destination: DST}
	for i := range N_RUNS {
		start := time.Now()
		_, err := paClient.GetPaths(context.TODO(), &paReq)
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalln(err)
		}
		_, err = paClient.Refresh(context.TODO(), &emptypb.Empty{})
		if err != nil {
			log.Fatalln(err)
		}
		results[3][i] = elapsed
	}
}

func executeBasePtc5() {
	// load policy A
	f, err := os.Open("./conflict-resolution/policy-a.lp")
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

	policyA := string(buf)
	_ = f.Close()

	// load policy B
	f, err = os.Open("./conflict-resolution/policy-b.lp")
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

	policyB := string(buf)
	_ = f.Close()

	// load meta-policy
	f, err = os.Open("./conflict-resolution/meta-policy.lp")
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

	metaPolicy := string(buf)
	_ = f.Close()

	pmReqA := pmpb.CreatePolicyRequest{Source: string(policyA)}
	pmReqB := pmpb.CreatePolicyRequest{Source: string(policyB)}
	pmReqMeta := pmpb.SetMetaPolicyRequest{Source: string(metaPolicy)}

	_, err = pmClient.CreatePolicy(context.TODO(), &pmReqA)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = pmClient.CreatePolicy(context.TODO(), &pmReqB)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = pmClient.SetMetaPolicy(context.TODO(), &pmReqMeta)
	if err != nil {
		log.Fatalln(err)
	}

	paReq := papb.GetPathsRequest{Destination: DST}
	for i := range N_RUNS {
		start := time.Now()
		_, err := paClient.GetPaths(context.TODO(), &paReq)
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalln(err)
		}
		_, err = paClient.Refresh(context.TODO(), &emptypb.Empty{})
		if err != nil {
			log.Fatalln(err)
		}
		results[4][i] = elapsed
	}
}

func setupBase() {
	// initialize connection to scion daemon
	scionDaemon = &daemon.Service{Address: ADDR_SCIOND}
	conn, err := scionDaemon.Connect(context.TODO())
	if err != nil {
		log.Fatalln(err)
	}
	scionDaemonConn = conn

	// initialize connection to path-analyzer service
	paConn, err = grpc.NewClient(ADDR_PATH_ANALYZER, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln(err)
	}
	paClient = papb.NewPathAnalyzerClient(paConn)

	// initialize connection to policy-manager service
	pmConn, err = grpc.NewClient(ADDR_POLICY_MANAGER, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln(err)
	}
	pmClient = pmpb.NewPolicyManagerClient(pmConn)
}

func cleanBase() {
	if _, err := pmClient.ResetPolicies(context.TODO(), &emptypb.Empty{}); err != nil {
		log.Println("ERROR: failed to reset policies:", err)
	}
	if _, err := paClient.Refresh(context.TODO(), &emptypb.Empty{}); err != nil {
		log.Println("ERROR: failed to refresh paths:", err)
	}
}

func saveBaseResults() {
	f, err := os.Create(OUTPUT_FILE)
	if err != nil {
		log.Fatalln(err)
	}

	line := ""
	for test := range N_TEST {
		line += fmt.Sprintf("PTC%d", test+1)
		if test < N_TEST-1 {
			line += "\t"
		}
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		log.Fatalln(err)
	}

	for run := range N_RUNS {
		line := ""
		for test := range N_TEST {
			line += fmt.Sprintf("%d", results[test][run].Milliseconds())
			if test < N_TEST-1 {
				line += "\t"
			}
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			log.Fatalln(err)
		}
	}
}
