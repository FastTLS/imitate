package catalog

import (
	"errors"
	. "github.com/FastTLS/fastls/profile"
	"strings"
	"testing"
)

func TestLegacyCatalogIntegrityAndIsolation(t *testing.T) {
	if legacyErr != nil {
		t.Fatal(legacyErr)
	}
	if len(legacyData.Records) != 31 || len(legacyData.JA4R) != 5 {
		t.Fatal("review legacy catalog inventory changes")
	}
	for _, r := range legacyData.Records {
		if err := validateLegacy(r); err != nil {
			t.Fatal(err)
		}
		if len(r.Source.Head) != 40 || len(r.Source.SHA256) != 64 {
			t.Errorf("missing source identity: %s", r.Name)
		}
		p, err := LookupLegacy(r.Name)
		if err != nil {
			t.Fatal(err)
		}
		if p.HTTP2 != nil {
			if p.HTTP2.HeaderPriority != nil {
				p.HTTP2.HeaderPriority.Weight = 0
			}
			if len(p.HTTP2.PriorityFrames) > 0 {
				p.HTTP2.PriorityFrames[0].Weight = 0
			}
		}
		if len(p.Headers) > 0 {
			p.Headers[0].Value = "changed"
		}
		if len(p.HeaderOrder) > 0 {
			p.HeaderOrder[0] = "changed"
		}
		if len(p.PseudoHeaderOrder) > 0 {
			p.PseudoHeaderOrder[0] = "changed"
		}
		if len(p.DeleteHeaders) > 0 {
			p.DeleteHeaders[0] = "changed"
		}
		if p.RandomExtensions != nil && len(p.RandomExtensions.Optional) > 0 {
			p.RandomExtensions.Optional[0] = "changed"
		}
		q, err := LookupLegacy(r.Name)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateLegacy(q); err != nil {
			t.Fatalf("mutation leaked from %s: %v", r.Name, err)
		}
	}
	if _, err := LookupLegacy("absent"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatal("unknown legacy record error lost")
	}
	if _, err := LegacyJA4R("legacy/chrome-150"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatal("must not invent JA4R for imported JA3")
	}
}

func TestLegacyValidationRejectsUnsafeAdapterData(t *testing.T) {
	base, err := LookupLegacy("legacy/chromium-142-random-priority")
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*LegacyPreset){
		"zero priority":          func(p *LegacyPreset) { p.HTTP2.HeaderPriority.Weight = 0 },
		"large priority":         func(p *LegacyPreset) { p.HTTP2.HeaderPriority.Weight = 257 },
		"invented verification":  func(p *LegacyPreset) { p.VerifiedFields = []string{"tls"} },
		"unsupported randomizer": func(p *LegacyPreset) { p.RandomExtensions.Strategy = "unknown" },
		"duplicate extension": func(p *LegacyPreset) {
			p.RandomExtensions.Extensions = append(p.RandomExtensions.Extensions, p.RandomExtensions.Extensions[0])
		},
		"absent optional extension":    func(p *LegacyPreset) { p.RandomExtensions.Optional = []string{"999"} },
		"malformed random fingerprint": func(p *LegacyPreset) { p.Fingerprint = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			p := cloneLegacy(base)
			edit(&p)
			if validateLegacy(p) == nil {
				t.Fatal("invalid adapter data accepted")
			}
		})
	}
}

func TestLegacyBindingsAndRanges(t *testing.T) {
	bindings, err := ListLegacyBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 31 {
		t.Fatal("wrapper inventory changed")
	}
	for _, b := range bindings {
		if !strings.HasPrefix(b.EntryPoint, "imitate.") && !strings.HasPrefix(b.EntryPoint, "ja4r.") {
			t.Fatal("invalid wrapper name")
		}
		if len(b.Source.SHA256) != 64 || b.Source.Path == "" {
			t.Fatal("binding has no source")
		}
		if _, err := LookupLegacy(b.Record); err != nil {
			t.Fatal(err)
		}
	}
	bindings[0].Record = "mutated"
	next, _ := ListLegacyBindings()
	if next[0].Record == "mutated" {
		t.Fatal("binding slice leaked")
	}
	rules, err := LegacyVersionRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatal("version rules omitted")
	}
	rules[0].Ranges[0].Record = "mutated"
	again, _ := LegacyVersionRules()
	if again[0].Ranges[0].Record == "mutated" {
		t.Fatal("version range leaked")
	}
	for _, test := range []struct {
		company string
		version int
		record  string
	}{
		{"Google Chrome", 105, "legacy/chrome-105"},
		{"Google Chrome", 106, "legacy/chrome-115"},
		{"Google Chrome", 142, "legacy/chromium-142-random-priority"},
		{"Microsoft Edge", 150, "legacy/chrome-150"},
		{"Firefox", 131, "legacy/firefox-131-priority-tree"},
		{"Firefox", 132, "legacy/firefox-144"},
		{"Firefox", 148, "legacy/firefox-147"},
		{"Firefox", 99999, "legacy/firefox-151"},
		{"Safari", 0, "legacy/webkit-desktop-15.3"},
	} {
		got, err := LegacyUARoute(test.company, test.version)
		if err != nil || got != test.record {
			t.Errorf("%s/%d got %s %v", test.company, test.version, got, err)
		}
	}
}
