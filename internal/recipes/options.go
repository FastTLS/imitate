package recipes

import "github.com/FastTLS/fastls/profile"

type fingerprint interface {
	Value() string
	Type() string
}
type Ja3Fingerprint struct{ FingerprintValue string }

func (f Ja3Fingerprint) Value() string { return f.FingerprintValue }
func (f Ja3Fingerprint) Type() string  { return "ja3" }

type Ja4Fingerprint struct{ FingerprintValue string }

func (f Ja4Fingerprint) Value() string { return f.FingerprintValue }
func (f Ja4Fingerprint) Type() string  { return "ja4r" }

type Options struct {
	Headers                           map[string]string
	UserAgent                         string
	Fingerprint                       fingerprint
	HTTP2Settings                     *profile.HTTP2Config
	HTTP2SettingsString               string
	PHeaderOrderKeys, HeaderOrderKeys []string
}
