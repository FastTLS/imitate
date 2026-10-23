package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	. "github.com/FastTLS/fastls/profile"
	"slices"
	"strconv"
	"strings"
)

// BuiltinSelection is a compatibility recipe, not an editable executable Spec.
type BuiltinSelection struct {
	ID            string   `json:"id"`
	Record        string   `json:"record"`
	Projection    string   `json:"projection"`
	Product       string   `json:"product"`
	Version       string   `json:"version"`
	EngineVersion string   `json:"engine_version,omitempty"`
	Platform      string   `json:"platform"`
	Identity      string   `json:"identity"`
	Compatible    bool     `json:"compatible"`
	Notes         []string `json:"notes"`
}

type builtinCatalog struct {
	SchemaVersion int                `json:"schema_version"`
	Description   string             `json:"description"`
	Records       []BuiltinSelection `json:"records"`
	Aliases       []Alias            `json:"aliases"`
}

var builtinData, builtinErr = loadBuiltinSelectors()

func loadBuiltinSelectors() (builtinCatalog, error) {
	var c builtinCatalog
	b, err := legacyFiles.ReadFile("data/builtin-selectors.json")
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
		return c, fmt.Errorf("unsupported built-in selector schema")
	}
	seen := map[string]bool{}
	for _, r := range c.Records {
		if seen[r.ID] || r.ID == "" {
			return c, fmt.Errorf("duplicate/empty built-in selector %q", r.ID)
		}
		seen[r.ID] = true
		if err := ValidateID(Spec{ID: r.ID, Metadata: Metadata{Kind: "browser", Product: r.Product, Platform: r.Platform, ProductVersion: r.Version, Variant: selectionVariant(r.ID)}}); err != nil {
			return c, err
		}
		if _, err := LookupLegacy(r.Record); err != nil {
			return c, err
		}
		if r.Projection == "ja4r" {
			if _, err := LegacyJA4R(r.Record); err != nil {
				return c, err
			}
		} else if r.Projection != "ja3" {
			return c, fmt.Errorf("invalid selection projection")
		}
		if r.Identity != "record" && r.Identity != "chromium" && r.Identity != "firefox" && r.Identity != "opera" {
			return c, fmt.Errorf("unknown selection identity")
		}
		if r.Identity == "chromium" || r.Identity == "opera" {
			v := r.Version
			if r.Identity == "opera" {
				v = r.EngineVersion
			}
			major, err := strconv.Atoi(v)
			if err != nil || major < 1 || major > 1000000 {
				return c, fmt.Errorf("invalid Chromium identity range")
			}
		}
		if r.Identity == "firefox" {
			major, err := strconv.Atoi(r.Version)
			if err != nil || major < 1 {
				return c, fmt.Errorf("invalid Firefox identity")
			}
		}
	}
	aliases := map[string]bool{}
	for _, a := range c.Aliases {
		if a.Name == "" || a.Name != strings.ToLower(strings.TrimSpace(a.Name)) || aliases[a.Name] || !seen[a.Target] || seen[a.Name] {
			return c, fmt.Errorf("invalid built-in alias %s", a.Name)
		}
		aliases[a.Name] = true
	}
	return c, nil
}

func selectionVariant(id string) string {
	p := strings.Split(id, "/")
	if len(p) == 4 {
		return p[3]
	}
	return ""
}

func LookupBuiltinSelection(selector string) (BuiltinSelection, error) {
	if builtinErr != nil {
		return BuiltinSelection{}, builtinErr
	}
	key := strings.ToLower(strings.TrimSpace(selector))
	for _, a := range builtinData.Aliases {
		if key == a.Name {
			key = a.Target
			break
		}
	}
	for _, r := range builtinData.Records {
		if key == r.ID {
			r.Notes = slices.Clone(r.Notes)
			return r, nil
		}
	}
	return BuiltinSelection{}, fmt.Errorf("%w: %q", ErrUnknownProfile, selector)
}

func ListBuiltinSelections() ([]BuiltinSelection, error) {
	if builtinErr != nil {
		return nil, builtinErr
	}
	out := slices.Clone(builtinData.Records)
	for i := range out {
		out[i].Notes = slices.Clone(out[i].Notes)
	}
	return out, nil
}
