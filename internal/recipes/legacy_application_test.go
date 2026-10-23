package recipes

import (
	frozen "github.com/FastTLS/imitate/internal/catalog"
	"testing"
)

func TestLegacyApplicationPreservesEveryExplicitDefault(t *testing.T) {
	for _, name := range []string{"Chrome120", "Chrome142", "Chrome150", "Firefox144", "Firefox147", "Firefox148", "Firefox151", "Firefox158", "Safari"} {
		t.Run(name, func(t *testing.T) {
			p, err := frozen.LookupLegacy(name)
			if err != nil {
				t.Fatal(err)
			}
			o := Options{Headers: map[string]string{}}
			for _, h := range p.Headers {
				o.Headers[h.Name] = "provided"
			}
			applyLegacy(&o, name, p.HTTP2Settings)
			for _, h := range p.Headers {
				want := h.Value
				if h.IfEmpty {
					want = "provided"
				}
				if got := o.Headers[h.Name]; got != want {
					t.Errorf("%s: got %q want %q", h.Name, got, want)
				}
			}
		})
	}
}

func TestLegacyPublicSettingsRemainOverridable(t *testing.T) {
	original := Chrome150HTTP2SettingsString
	t.Cleanup(func() { Chrome150HTTP2SettingsString = original })
	Chrome150HTTP2SettingsString = "4:65535|1|0|m,a,s,p"
	o := Options{}
	Chrome150(&o)
	if o.HTTP2SettingsString != Chrome150HTTP2SettingsString {
		t.Fatal("migration ignored existing public settings variable")
	}
}

func TestExportedFingerprintConstantsMatchMigrationData(t *testing.T) {
	for name, want := range map[string]string{"Chrome150": Chrome150JA3, "Firefox151": Firefox151JA3, "Firefox158": Firefox158JA3} {
		p, err := frozen.LookupLegacy(name)
		if err != nil {
			t.Fatal(err)
		}
		if p.Fingerprint != want {
			t.Errorf("public compatibility constant differs from %s data", name)
		}
	}
}
