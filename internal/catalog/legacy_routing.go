package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	. "github.com/FastTLS/fastls/profile"
)

type legacyRouting struct {
	SchemaVersion int                  `json:"schema_version"`
	Chromium      []LegacyVersionRange `json:"chromium_routes"`
	Firefox       []LegacyVersionRange `json:"firefox_routes"`
}

var routingData, routingErr = loadLegacyRouting()

func loadLegacyRouting() (legacyRouting, error) {
	var c legacyRouting
	b, err := legacyFiles.ReadFile("data/legacy-consumer-routing.json")
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
		return c, fmt.Errorf("unsupported legacy routing schema")
	}
	for _, ranges := range [][]LegacyVersionRange{c.Chromium, c.Firefox} {
		if len(ranges) == 0 || ranges[len(ranges)-1].MaxVersion != 0 {
			return c, fmt.Errorf("missing final legacy range")
		}
		previous := 0
		for i, r := range ranges {
			if i < len(ranges)-1 && r.MaxVersion <= previous {
				return c, fmt.Errorf("unordered legacy ranges")
			}
			previous = r.MaxVersion
			if _, err := LookupLegacy(r.Record); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// LegacyUARoute returns the historical baseline for an already parsed UA.
// It does not accept or validate a selector or prove compatibility with a client.
func LegacyUARoute(company string, version int) (string, error) {
	if routingErr != nil {
		return "", routingErr
	}
	if company == "Safari" {
		return "legacy/webkit-desktop-15.3", nil
	}
	if company != "Google Chrome" && company != "Microsoft Edge" && company != "Opera" && company != "Firefox" {
		return "", fmt.Errorf("%w: unknown legacy UA company %q", ErrUnknownProfile, company)
	}
	ranges := routingData.Chromium
	if company == "Firefox" {
		ranges = routingData.Firefox
	}
	for _, r := range ranges {
		if r.MaxVersion == 0 || version <= r.MaxVersion {
			return r.Record, nil
		}
	}
	return "", fmt.Errorf("%w: legacy UA route", ErrUnknownProfile)
}
