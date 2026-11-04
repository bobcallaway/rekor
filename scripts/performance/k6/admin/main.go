// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This command retires the previous run's disposable benchmark trees. It must
// only be connected to the isolated benchmark Trillian instance.
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/google/trillian"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func main() {
	address := flag.String("address", "trillian:8090", "isolated benchmark admin endpoint")
	flag.Parse()
	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := trillian.NewTrillianAdminClient(conn)
	trees, err := client.ListTrees(ctx, &trillian.ListTreesRequest{}, grpc.WaitForReady(true))
	if err != nil {
		panic(err)
	}
	frozen := 0
	for _, tree := range trees.Tree {
		if tree.TreeState != trillian.TreeState_ACTIVE {
			continue
		}
		tree.TreeState = trillian.TreeState_FROZEN
		_, err := client.UpdateTree(ctx, &trillian.UpdateTreeRequest{Tree: tree, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tree_state"}}})
		if err != nil {
			panic(err)
		}
		frozen++
	}
	fmt.Printf("Retired %d previous benchmark trees\n", frozen)
}
