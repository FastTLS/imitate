// Package imitate generates bounded client fingerprints without a request backend.
package imitate

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/imitate/internal/catalog"
	"github.com/FastTLS/imitate/internal/recipes"
)

const ChromiumVersionMin = 100
const ChromiumVersionMax = 160
const Version = "0.1.0-dev.20261023.8"
const DataRevision = "recipes-20261023.3"

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Resolve(ctx context.Context, r profile.ResolveRequest) (profile.Resolution, error) {
	if err := ctx.Err(); err != nil {
		return profile.Resolution{}, err
	}
	if p == nil {
		return profile.Resolution{}, fmt.Errorf("%w: nil imitate provider", profile.ErrInvalidOptions)
	}
	if strings.HasPrefix(r.Selector, "library/") || strings.HasPrefix(r.Selector, "client/") {
		return resolveNative(ctx, r)
	}
	opts := []recipes.UseOption{recipes.WithDefaults(r.Defaults)}
	if r.Policy != "" {
		opts = append(opts, recipes.WithPolicy(r.Policy))
	}
	o := recipes.Options{}
	m, err := recipes.Use(&o, r.Selector, opts...)
	if err != nil {
		return profile.Resolution{}, err
	}
	h := profile.HeaderPolicy{}
	keys := make([]string, 0, len(o.Headers))
	for k := range o.Headers {
		if !strings.EqualFold(k, "User-Agent") {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		h.Rules = append(h.Rules, profile.HeaderRule{Header: profile.Header{Name: k, Values: []string{o.Headers[k]}}, Mode: "default"})
	}
	m.ProviderID = "FastTLS/imitate"
	m.ProviderVersion = Version
	m.DataRevision = DataRevision
	m.ContractVersion = profile.ContractVersion
	if err = ctx.Err(); err != nil {
		return profile.Resolution{}, err
	}
	return profile.Resolution{Legacy: &profile.LegacyDefinition{Format: profile.LegacyFormat(o.Fingerprint.Type()), Hello: o.Fingerprint.Value(), UserAgent: o.UserAgent, HTTP2: o.HTTP2Settings, HTTP2Settings: o.HTTP2SettingsString, HeaderOrder: o.HeaderOrderKeys, PseudoOrder: o.PHeaderOrderKeys}, Headers: h, Match: m}, nil
}

// List returns finite supported IDs. It never invents future browser versions.
func (p *Provider) List() ([]string, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil provider", profile.ErrInvalidOptions)
	}
	a, err := catalog.ListBuiltinSelections()
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, s := range a {
		ids = append(ids, s.ID)
	}
	ids = append(ids, nativeIDs...)
	slices.Sort(ids)
	return ids, nil
}
func GenerateSecChUa(seed int, brand string) (string, error) {
	if seed < 100 || seed > 160 {
		return "", fmt.Errorf("%w: Chromium identity range 100..160", profile.ErrUnknownProfile)
	}
	return recipes.GenerateSecChUa(seed, brand), nil
}
func GenerateChromiumUserAgent(product string, version int, platform string) (string, error) {
	if version < 100 || version > 160 || (product != "chrome" && product != "edge" && product != "chromium") {
		return "", profile.ErrUnknownProfile
	}
	switch platform {
	case "windows":
		platform = "win"
	case "macos":
		platform = "mac"
	case "linux", "android", "win", "mac":
	default:
		return "", profile.ErrUnknownProfile
	}
	return recipes.GenerateChromiumUserAgent(product, version, platform), nil
}
