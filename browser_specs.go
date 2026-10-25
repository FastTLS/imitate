package imitate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/FastTLS/fastls/profile"
	"slices"
)

// Canonical browser recipes contain complete neutral Specs, not JA3/JA4R
// projections. The legacy recipe package exists only for historical input APIs.
//
//go:embed browser-specs.json
var browserSpecData []byte

var browserSpecs = func() map[string]profile.Resolution {
	var entries map[string]profile.Resolution
	if err := json.Unmarshal(browserSpecData, &entries); err != nil {
		panic(err)
	}
	for id, r := range entries {
		if r.Spec == nil || r.Legacy != nil {
			panic(fmt.Sprintf("%s: complete Spec required", id))
		}
		h := r.Spec.Headers
		if len(h.HTTP1Defaults)+len(h.HTTP2Defaults)+len(h.HTTP1Order) > 0 && !slices.Contains(r.Spec.Capabilities.RequiredFeatures, "http.headers.protocol.v1") {
			panic(fmt.Sprintf("%s: protocol headers require explicit backend capability", id))
		}
	}
	return entries
}()
