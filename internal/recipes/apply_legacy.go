package recipes

import (
	frozen "github.com/FastTLS/imitate/internal/catalog"
	"strings"
)

func legacyHTTP2(name string) string {
	p, err := frozen.LookupLegacy(name)
	if err != nil {
		return ""
	}
	return p.HTTP2Settings
}

// Legacy wrappers retain their old overwrite policy. This is not complete Spec compilation.
// Embedded data integrity is a release check; invalid data leaves Options untouched.
func applyLegacy(options *Options, name, http2 string) {
	p, err := frozen.LookupLegacy(name)
	if err != nil {
		return
	}
	fingerprint := p.Fingerprint
	if name == "Chrome120" {
		fingerprint = strings.Replace(fingerprint, "<random-permutation;optional-padding21;psk41-last>", shuffleExtension(chrome120Extension, 7)+"-41", 1)
	}
	options.Fingerprint = Ja3Fingerprint{FingerprintValue: fingerprint}
	options.HTTP2SettingsString = http2
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}
	for _, h := range p.Headers {
		if !h.IfEmpty || options.Headers[h.Name] == "" {
			options.Headers[h.Name] = h.Value
		}
	}
	if p.SetHeaderOrder {
		options.HeaderOrderKeys = append([]string(nil), p.HeaderOrder...)
	}
	options.UserAgent = p.UserAgent
}
