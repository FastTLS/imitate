package recipes

import (
	"encoding/json"
	"fmt"
	frozen "github.com/FastTLS/imitate/internal/catalog"
	"os"
	"slices"
	"strings"
	"testing"
)

func consumerFixtures(t *testing.T) (map[string]string, map[string]string, map[string]string, map[string]string) {
	t.Helper()
	var inventory struct {
		EntryPoints map[string]string `json:"entrypoints"`
	}
	b, err := os.ReadFile("../../testdata/consumer-inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &inventory); err != nil {
		t.Fatal(err)
	}
	return nil, nil, nil, inventory.EntryPoints
}
func normalizeConsumerRandom(t *testing.T, o *Options, name string) {
	t.Helper()
	p, err := frozen.LookupLegacy(name)
	if err != nil {
		t.Fatal(err)
	}
	r := p.RandomExtensions
	if r == nil {
		return
	}
	parts := strings.Split(o.Fingerprint.Value(), ",")
	if len(parts) != 5 {
		t.Fatal("malformed random JA3")
	}
	actual := strings.Split(parts[2], "-")
	seen := map[string]bool{}
	for _, id := range actual {
		if seen[id] || !slices.Contains(r.Extensions, id) {
			t.Fatalf("duplicate/unexpected random extension %s", id)
		}
		seen[id] = true
	}
	for _, id := range r.Extensions {
		if !seen[id] && !slices.Contains(r.Optional, id) {
			t.Fatalf("missing required random extension %s", id)
		}
	}
	parts[2] = "<legacy-random-extensions>"
	o.Fingerprint = Ja3Fingerprint{FingerprintValue: strings.Join(parts, ",")}
}
func TestImportedRandomRulesAndOwnership(t *testing.T) {
	_, _, _, entries := consumerFixtures(t)
	for entry, name := range entries {
		t.Run(entry, func(t *testing.T) {
			p, err := frozen.LookupLegacy(name)
			if err != nil {
				t.Fatal(err)
			}
			if !p.Legacy || len(p.VerifiedFields) != 0 {
				t.Fatal("legacy is not live verification")
			}
			for i := 0; i < 64; i++ {
				o := Options{}
				if err := applyImportedLegacy(&o, name); err != nil {
					t.Fatal(err)
				}
				normalizeConsumerRandom(t, &o, name)
			}
			if p.HTTP2 != nil && len(p.HTTP2.Settings) > 0 {
				old := p.HTTP2.Settings[0].Value
				p.HTTP2.Settings[0].Value++
				q, _ := frozen.LookupLegacy(name)
				if q.HTTP2.Settings[0].Value != old {
					t.Fatal("lookup leaked settings")
				}
				if p.HTTP2.HeaderPriority != nil {
					p.HTTP2.HeaderPriority.Weight = 1
				}
				if len(p.HTTP2.PriorityFrames) > 0 {
					p.HTTP2.PriorityFrames[0].Weight = 1
				}
			}
			if p.RandomExtensions != nil {
				old := p.RandomExtensions.Extensions[0]
				p.RandomExtensions.Extensions[0] = "mutated"
				q, _ := frozen.LookupLegacy(name)
				if q.RandomExtensions.Extensions[0] != old {
					t.Fatal("lookup leaked random strategy")
				}
			}
		})
	}
	o := Options{UserAgent: "preserved"}
	if err := applyImportedLegacy(&o, "missing"); err == nil || o.UserAgent != "preserved" {
		t.Fatal("unknown legacy record mutated options")
	}
	if err := applyImportedLegacy(nil, entries["Chrome150"]); err == nil {
		t.Fatal(fmt.Errorf("nil options accepted"))
	}
}
