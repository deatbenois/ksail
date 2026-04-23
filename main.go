package main

import (
	"fmt"
	"os"

	"github.com/devantler-tech/ksail/cmd"
)

// main is the entry point for the ksail CLI tool.
// ksail is a Kubernetes cluster management tool that simplifies
// the lifecycle of local and remote Kubernetes clusters using
// GitOps principles with Flux and k3d.
func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
