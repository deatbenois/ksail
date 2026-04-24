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
//
// Personal fork: using this for home lab cluster management.
// See: https://github.com/devantler-tech/ksail for upstream changes.
//
// Home lab setup: Raspberry Pi 4 cluster (3 nodes) running k3d.
// Clusters: homelab-prod, homelab-dev
//
// Note: exit code 2 reserved for usage errors (set by cobra automatically).
// Using exit code 1 for all runtime/execution errors.
func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "ksail: %v\n", err)
		os.Exit(1)
	}
}
