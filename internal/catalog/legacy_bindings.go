package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	. "github.com/FastTLS/fastls/profile"
	"slices"
)

// LegacyBinding identifies a public legacy wrapper and its data/identity source.
// It is inventory metadata, not a structured Spec or a selector policy.
type LegacyBinding struct {
	EntryPoint   string       `json:"entrypoint"`
	Record       string       `json:"record"`
	Projection   string       `json:"projection"`
	IdentityRule string       `json:"identity_rule"`
	Version      int          `json:"version"`
	Source       LegacySource `json:"source"`
}

type LegacyVersionRange struct {
	MaxVersion int    `json:"max_version"` // Zero denotes the final unbounded legacy range.
	Record     string `json:"record"`
}

type LegacyVersionRule struct {
	Name       string               `json:"name"`
	Minimum    int                  `json:"minimum,omitempty"`
	Maximum    int                  `json:"maximum,omitempty"`
	Default    int                  `json:"default,omitempty"`
	OutOfRange string               `json:"out_of_range"`
	Ranges     []LegacyVersionRange `json:"ranges"`
}

type legacyBindings struct {
	SchemaVersion int                 `json:"schema_version"`
	Description   string              `json:"description"`
	EntryPoints   []LegacyBinding     `json:"entrypoints"`
	VersionRules  []LegacyVersionRule `json:"version_rules"`
}

var bindingData, bindingErr = loadLegacyBindings()

func loadLegacyBindings() (legacyBindings, error) {
	var c legacyBindings
	b, err := legacyFiles.ReadFile("data/legacy-entrypoints.json")
	if err != nil {
		return c, err
	}
	if err = CheckJSONValue(json.NewDecoder(bytes.NewReader(b)), 0); err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if c.SchemaVersion != SchemaVersion {
		return c, fmt.Errorf("unsupported legacy binding schema")
	}
	seen := map[string]bool{}
	for _, e := range c.EntryPoints {
		if e.EntryPoint == "" || seen[e.EntryPoint] || (e.Projection != "ja3" && e.Projection != "ja4r") {
			return c, fmt.Errorf("invalid legacy binding %q", e.EntryPoint)
		}
		seen[e.EntryPoint] = true
		if _, err := LookupLegacy(e.Record); err != nil {
			return c, err
		}
		if e.Projection == "ja4r" {
			if _, err := LegacyJA4R(e.Record); err != nil {
				return c, err
			}
		}
	}
	for _, rule := range c.VersionRules {
		if rule.Name == "" || len(rule.Ranges) == 0 {
			return c, fmt.Errorf("invalid legacy version rule")
		}
		for _, r := range rule.Ranges {
			if _, err := LookupLegacy(r.Record); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

func ListLegacyBindings() ([]LegacyBinding, error) {
	if bindingErr != nil {
		return nil, bindingErr
	}
	return slices.Clone(bindingData.EntryPoints), nil
}

func LegacyVersionRules() ([]LegacyVersionRule, error) {
	if bindingErr != nil {
		return nil, bindingErr
	}
	rules := slices.Clone(bindingData.VersionRules)
	for i := range rules {
		rules[i].Ranges = slices.Clone(rules[i].Ranges)
	}
	return rules, nil
}
