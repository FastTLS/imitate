package catalog

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	. "github.com/FastTLS/fastls/profile"
	"slices"
)

//go:embed data/legacy-presets.json data/legacy-consumer.json data/legacy-entrypoints.json data/legacy-consumer-routing.json data/builtin-selectors.json
var legacyFiles embed.FS

type LegacyHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IfEmpty bool   `json:"if_empty"`
}

// LegacyPreset is transitional compatibility data, not an executable complete Spec.
type LegacyPreset struct {
	Name                 string                  `json:"name"`
	Metadata             Metadata                `json:"metadata"`
	FingerprintType      string                  `json:"fingerprint_type"`
	Fingerprint          string                  `json:"fingerprint"`
	HTTP2Settings        string                  `json:"http2_settings"`
	HTTP2                *HTTP2Config            `json:"http2,omitempty"`
	PseudoHeaderOrder    []string                `json:"pseudo_header_order,omitempty"`
	SetPseudoHeaderOrder bool                    `json:"set_pseudo_header_order,omitempty"`
	UserAgent            string                  `json:"user_agent"`
	PreserveUserAgent    bool                    `json:"preserve_user_agent,omitempty"`
	Headers              []LegacyHeader          `json:"headers"`
	HeaderOrder          []string                `json:"header_order"`
	SetHeaderOrder       bool                    `json:"set_header_order"`
	DeleteHeaders        []string                `json:"delete_headers,omitempty"`
	RandomExtensions     *LegacyRandomExtensions `json:"random_extensions,omitempty"`
	Source               LegacySource            `json:"source"`
	Legacy               bool                    `json:"legacy"`
	VerifiedFields       []string                `json:"verified_fields"`
}

// LegacyRandomExtensions preserves an existing generator, not a recommended
// distribution for new profiles. Optional values are removed before swapping.
type LegacyRandomExtensions struct {
	Strategy   string   `json:"strategy"`
	Extensions []string `json:"extensions"`
	Optional   []string `json:"optional"`
}
type legacyCatalog struct {
	SchemaVersion int               `json:"schema_version"`
	Description   string            `json:"description"`
	Records       []LegacyPreset    `json:"records"`
	JA4R          map[string]string `json:"ja4r"`
}

var legacyData, legacyErr = loadLegacy()

func readLegacy(path string) (legacyCatalog, error) {
	var c legacyCatalog
	b, err := legacyFiles.ReadFile(path)
	if err != nil {
		return c, err
	}
	// The duplicate-key scan is shared with catalog loading.
	if err = CheckJSONValue(json.NewDecoder(bytes.NewReader(b)), 0); err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if c.SchemaVersion != SchemaVersion {
		return c, fmt.Errorf("unsupported legacy schema")
	}
	seen := map[string]bool{}
	for _, r := range c.Records {
		if r.Name == "" || seen[r.Name] || r.Fingerprint == "" || r.Source.Path == "" || !r.Legacy {
			return c, fmt.Errorf("invalid legacy record %s", r.Name)
		}
		seen[r.Name] = true
		if err := validateLegacy(r); err != nil {
			return c, err
		}
	}
	return c, nil
}

func validateLegacy(r LegacyPreset) error {
	if len(r.VerifiedFields) != 0 {
		return fmt.Errorf("legacy record %s must not claim verification", r.Name)
	}
	if h := r.HTTP2; h != nil {
		priorities := slices.Clone(h.PriorityFrames)
		if h.HeaderPriority != nil {
			priorities = append(priorities, *h.HeaderPriority)
		}
		for _, p := range priorities {
			if p.Weight < 1 || p.Weight > 256 {
				return fmt.Errorf("legacy record %s has invalid priority weight", r.Name)
			}
		}
	}
	if random := r.RandomExtensions; random != nil {
		if random.Strategy != "legacy-swap-permutation" || len(random.Extensions) == 0 {
			return fmt.Errorf("invalid random rule %s", r.Name)
		}
		seen := map[string]bool{}
		for _, id := range random.Extensions {
			if seen[id] {
				return fmt.Errorf("duplicate random extension %s", r.Name)
			}
			seen[id] = true
		}
		for _, id := range random.Optional {
			if !seen[id] {
				return fmt.Errorf("optional extension absent in %s", r.Name)
			}
		}
		if len(bytes.Split([]byte(r.Fingerprint), []byte(","))) != 5 {
			return fmt.Errorf("invalid random JA3 %s", r.Name)
		}
	}
	return nil
}

func loadLegacy() (legacyCatalog, error) {
	c, err := readLegacy("data/legacy-presets.json")
	if err != nil {
		return c, err
	}
	imported, err := readLegacy("data/legacy-consumer.json")
	if err != nil {
		return c, err
	}
	seen := map[string]bool{}
	for _, r := range c.Records {
		seen[r.Name] = true
	}
	for _, r := range imported.Records {
		if seen[r.Name] {
			return c, fmt.Errorf("duplicate legacy record %s", r.Name)
		}
		seen[r.Name] = true
		c.Records = append(c.Records, r)
	}
	return c, nil
}

func cloneLegacy(r LegacyPreset) LegacyPreset {
	r.Headers = slices.Clone(r.Headers)
	r.HeaderOrder = slices.Clone(r.HeaderOrder)
	r.PseudoHeaderOrder = slices.Clone(r.PseudoHeaderOrder)
	r.DeleteHeaders = slices.Clone(r.DeleteHeaders)
	r.VerifiedFields = slices.Clone(r.VerifiedFields)
	if r.HTTP2 != nil {
		h := Clone(Spec{HTTP2: *r.HTTP2}).HTTP2
		r.HTTP2 = &h
	}
	if r.RandomExtensions != nil {
		v := *r.RandomExtensions
		v.Extensions = slices.Clone(v.Extensions)
		v.Optional = slices.Clone(v.Optional)
		r.RandomExtensions = &v
	}
	return r
}
func LookupLegacy(name string) (LegacyPreset, error) {
	if legacyErr != nil {
		return LegacyPreset{}, legacyErr
	}
	for _, r := range legacyData.Records {
		if r.Name == name {
			return cloneLegacy(r), nil
		}
	}
	return LegacyPreset{}, fmt.Errorf("%w: legacy/%s", ErrUnknownProfile, name)
}
func LegacyJA4R(name string) (string, error) {
	if legacyErr != nil {
		return "", legacyErr
	}
	v, ok := legacyData.JA4R[name]
	if !ok {
		return "", fmt.Errorf("%w: legacy JA4R/%s", ErrUnknownProfile, name)
	}
	return v, nil
}
