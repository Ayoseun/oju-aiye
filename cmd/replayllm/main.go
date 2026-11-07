// replayllm is a scripted stand-in for a local model server (Ollama) for testing the
// pipeline end to end without a GPU. See internal/replay.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"vuln-research/internal/replay"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:11435", "listen address")
	scenario := flag.String("scenario", "testdata/scenarios/traversal", "directory with scout/investigator/reviewer .json replies")
	flag.Parse()

	srv, err := replay.New(*scenario)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "replayllm: serving scenario %s on http://%s/v1\n", *scenario, *addr)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}
