// Package imitate generates bounded client fingerprints without a request backend.
package imitate

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/imitate/internal/recipes"
)

const ChromiumVersionMin = 100
const ChromiumVersionMax = 160
const Version = "0.1.0"
const DataRevision = "recipes-20261025.1"

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Resolve(ctx context.Context, r profile.ResolveRequest) (profile.Resolution, error) {
	if err := ctx.Err(); err != nil {
		return profile.Resolution{}, err
	}
	if p == nil {
		return profile.Resolution{}, fmt.Errorf("%w: nil imitate provider", profile.ErrInvalidOptions)
	}
	if r.Selector == "" {
		r.Selector = r.Defaults.Selector
	}
	if strings.HasPrefix(r.Selector, "library/") || strings.HasPrefix(r.Selector, "client/") {
		return resolveNative(ctx, r)
	}
	selector := r.Selector
	if r.Policy != "" && r.Policy != profile.AllowCompatible && r.Policy != profile.RecordedOnly {
		return profile.Resolution{}, profile.ErrInvalidOptions
	}
	result, ok := browserSpecs[selector]
	if !ok || r.Policy == profile.RecordedOnly && result.Match.Method == "compatible" {
		return profile.Resolution{}, fmt.Errorf("%w: %s", profile.ErrUnknownProfile, selector)
	}
	result = profile.CloneResolution(result)
	result.Match.Selector = selector
	result.Match.ProviderID = "FastTLS/imitate"
	result.Match.ProviderVersion = Version
	result.Match.DataRevision = DataRevision
	result.Match.ContractVersion = profile.ContractVersion
	if err := profile.ValidateResolution(result); err != nil {
		return profile.Resolution{}, err
	}
	if err := ctx.Err(); err != nil {
		return profile.Resolution{}, err
	}
	return result, nil
}

// List returns finite supported IDs. It never invents future browser versions.
func (p *Provider) List() ([]string, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil provider", profile.ErrInvalidOptions)
	}
	ids := []string{}
	for id := range browserSpecs {
		ids = append(ids, id)
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
