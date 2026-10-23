package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/FastTLS/imitate"
)

func main() {
	output := flag.String("output", "fingerprints.json", "closed snapshot output")
	flag.Parse()
	bundle, err := imitate.New().Export(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err == nil {
		data = append(data, '\n')
		err = os.WriteFile(*output, data, 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"output": *output, "records": len(bundle.Records), "provider_version": imitate.Version, "data_revision": imitate.DataRevision, "sha256": fmt.Sprintf("%x", sha256.Sum256(data))})
}
