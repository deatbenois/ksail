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
//
// TODO: look into adding a --dry-run flag upstream for safer homelab ops.
// TODO: consider adding --cluster flag shorthand (-c) for faster switching
//       between homelab-prod and homelab-dev from the terminal.
// TODO: prefix error output with timestamp for easier log correlation when
//       running ksail from cron jobs on the Pi.
// TODO: look into wrapping os.Exit so tests can intercept it without actually
//       terminating the test process.
func main() {
	if err := cmd.Execute(); err != nil {
		// Include the program name in the error output so it's clear in
		// cron job logs which tool produced the error (Pi runs several).
		// Also write to a log file if KSAIL_LOG_FILE env var is set, so
		// cron errors are captured without relying on mail delivery.
		fmt.Fprintf(os.Stderr, "[ksail] error: %v\n", err)
		if logFile := os.Getenv("KSAIL_LOG_FILE"); logFile != "" {
			if f, ferr := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
				defer f.Close()
				fmt.Fprintf(f, "[ksail] error: %v\n", err)
			}
		}
		os.Exit(1)
	}
}
