package recipes

import (
	"fmt"
	"github.com/FastTLS/fastls/profile"
	frozen "github.com/FastTLS/imitate/internal/catalog"
	"math/rand"
	"slices"
	"strings"
)

// applyImportedLegacy is the compatibility adapter for reviewed historical
// records. It is deliberately private until C03 defines selection and policy.
// It preserves case-sensitive legacy mutations; Use will normalize separately.
func applyImportedLegacy(o *Options, name string) error {
	p, err := frozen.LookupLegacy(name)
	if err != nil {
		return err
	}
	if o == nil {
		return fmt.Errorf("nil options")
	}
	value := p.Fingerprint
	if r := p.RandomExtensions; r != nil {
		extensions := slices.Clone(r.Extensions)
		for _, optional := range r.Optional {
			if rand.Intn(2) == 1 {
				if i := slices.Index(extensions, optional); i >= 0 {
					extensions = append(extensions[:i], extensions[i+1:]...)
				}
			}
		}
		// Preserve the old swap algorithm, without promising its global PRNG sequence.
		for i := range extensions {
			j := rand.Intn(len(extensions))
			extensions[i], extensions[j] = extensions[j], extensions[i]
		}
		parts := strings.Split(value, ",")
		parts[2] = strings.Join(extensions, "-")
		value = strings.Join(parts, ",")
	}
	o.Fingerprint = Ja3Fingerprint{FingerprintValue: value}
	if p.HTTP2Settings != "" {
		o.HTTP2SettingsString = p.HTTP2Settings
	}
	if p.HTTP2 != nil {
		h := profile.Clone(profile.Spec{HTTP2: *p.HTTP2}).HTTP2
		o.HTTP2Settings = &h
	}
	if p.SetPseudoHeaderOrder {
		o.PHeaderOrderKeys = slices.Clone(p.PseudoHeaderOrder)
	}
	if p.SetHeaderOrder {
		o.HeaderOrderKeys = slices.Clone(p.HeaderOrder)
	}
	if o.Headers == nil {
		o.Headers = make(map[string]string)
	}
	for _, h := range p.Headers {
		if !h.IfEmpty || o.Headers[h.Name] == "" {
			o.Headers[h.Name] = h.Value
		}
	}
	for _, key := range p.DeleteHeaders {
		delete(o.Headers, key)
	}
	if !p.PreserveUserAgent {
		o.UserAgent = p.UserAgent
	}
	return nil
}
