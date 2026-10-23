package recipes

import (
	"encoding/json"
	catalog "github.com/FastTLS/imitate/internal/catalog"
	"os"
	"reflect"
	"strings"
	"testing"
)

func snapshotJA4(baseline string, apply func(*Options), version int) func(*Options) {
	return func(o *Options) {
		apply(o)
		value, err := catalog.LegacyJA4R(baseline)
		if err != nil {
			panic(err)
		}
		o.Fingerprint = Ja4Fingerprint{value}
		if version != 0 {
			setFirefoxUA(o, version)
		}
	}
}

type snapshotConfig struct {
	FingerprintType string `json:"fingerprint_type"`
	Options         struct {
		Headers     map[string]string `json:"headers"`
		UserAgent   string            `json:"userAgent"`
		Fingerprint struct {
			Value string `json:"value"`
		} `json:"fingerprint"`
		HTTP2 string `json:"http2SettingsString"`
	} `json:"options"`
	Order  []string `json:"header_order"`
	Pseudo []string `json:"pseudo_header_order"`
}

func TestHistoricalGeneratorSnapshots(t *testing.T) {
	b, err := os.ReadFile("../../testdata/legacy-options.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]snapshotConfig
	if err = json.Unmarshal(b, &golden); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, preset := range legacyPresets() {
		for _, state := range []string{"empty", "populated"} {
			t.Run(preset.name+"/"+state, func(t *testing.T) {
				o := Options{Headers: map[string]string{}}
				if state == "populated" {
					o.Headers = map[string]string{"Accept": "application/custom", "X-Custom": "keep", "User-Agent": "explicit-header", "Sec-Ch-Ua": "explicit-hints"}
					o.UserAgent = "explicit-ua"
					o.HeaderOrderKeys = []string{"x-custom", "accept"}
					o.PHeaderOrderKeys = []string{":path", ":method"}
					o.Fingerprint = Ja3Fingerprint{"explicit-fingerprint"}
				}
				preset.apply(&o)
				value := o.Fingerprint.Value()
				if preset.name == "imitate.Chrome120" {
					parts := strings.Split(value, ",")
					parts[2] = "<random-permutation;optional-padding21;psk41-last>"
					value = strings.Join(parts, ",")
				}
				var got snapshotConfig
				got.FingerprintType = o.Fingerprint.Type()
				got.Options.Headers = o.Headers
				got.Options.UserAgent = o.UserAgent
				got.Options.Fingerprint.Value = value
				got.Options.HTTP2 = o.HTTP2SettingsString
				got.Order = o.HeaderOrderKeys
				got.Pseudo = o.PHeaderOrderKeys
				want, ok := golden[preset.name+"/"+state]
				if !ok || !reflect.DeepEqual(got, want) {
					t.Fatalf("generator differs from original snapshot: got=%+v want=%+v", got, want)
				}
			})
			count++
		}
	}
	if count != len(golden) || count != 148 {
		t.Fatalf("snapshot inventory: checked %d, stored %d", count, len(golden))
	}
}
func legacyPresets() []struct {
	name  string
	apply func(*Options)
} {
	return []struct {
		name  string
		apply func(*Options)
	}{
		{"imitate.Chrome", Chrome},
		{"imitate.Chrome120", Chrome120},
		{"imitate.Chrome142", Chrome142},
		{"imitate.Chrome150", Chrome150},
		{"imitate.Chromium", Chromium},
		{"imitate.ChromeVersion/149", func(o *Options) { ChromeVersion(o, 149) }},
		{"imitate.ChromeVersion/150", func(o *Options) { ChromeVersion(o, 150) }},
		{"imitate.ChromeVersion/151", func(o *Options) { ChromeVersion(o, 151) }},
		{"imitate.ChromeVersion/152", func(o *Options) { ChromeVersion(o, 152) }},
		{"imitate.ChromeVersion/153", func(o *Options) { ChromeVersion(o, 153) }},
		{"imitate.ChromeVersion/154", func(o *Options) { ChromeVersion(o, 154) }},
		{"imitate.ChromeVersion/155", func(o *Options) { ChromeVersion(o, 155) }},
		{"imitate.ChromeVersion/156", func(o *Options) { ChromeVersion(o, 156) }},
		{"imitate.ChromeVersion/157", func(o *Options) { ChromeVersion(o, 157) }},
		{"imitate.ChromeVersion/158", func(o *Options) { ChromeVersion(o, 158) }},
		{"imitate.ChromeVersion/159", func(o *Options) { ChromeVersion(o, 159) }},
		{"imitate.ChromeVersion/160", func(o *Options) { ChromeVersion(o, 160) }},
		{"imitate.ChromeVersion/161", func(o *Options) { ChromeVersion(o, 161) }},
		{"imitate.EdgeVersion/149", func(o *Options) { EdgeVersion(o, 149) }},
		{"imitate.EdgeVersion/150", func(o *Options) { EdgeVersion(o, 150) }},
		{"imitate.EdgeVersion/151", func(o *Options) { EdgeVersion(o, 151) }},
		{"imitate.EdgeVersion/152", func(o *Options) { EdgeVersion(o, 152) }},
		{"imitate.EdgeVersion/153", func(o *Options) { EdgeVersion(o, 153) }},
		{"imitate.EdgeVersion/154", func(o *Options) { EdgeVersion(o, 154) }},
		{"imitate.EdgeVersion/155", func(o *Options) { EdgeVersion(o, 155) }},
		{"imitate.EdgeVersion/156", func(o *Options) { EdgeVersion(o, 156) }},
		{"imitate.EdgeVersion/157", func(o *Options) { EdgeVersion(o, 157) }},
		{"imitate.EdgeVersion/158", func(o *Options) { EdgeVersion(o, 158) }},
		{"imitate.EdgeVersion/159", func(o *Options) { EdgeVersion(o, 159) }},
		{"imitate.EdgeVersion/160", func(o *Options) { EdgeVersion(o, 160) }},
		{"imitate.EdgeVersion/161", func(o *Options) { EdgeVersion(o, 161) }},
		{"imitate.ChromiumVersion/149", func(o *Options) { ChromiumVersion(o, 149) }},
		{"imitate.ChromiumVersion/150", func(o *Options) { ChromiumVersion(o, 150) }},
		{"imitate.ChromiumVersion/151", func(o *Options) { ChromiumVersion(o, 151) }},
		{"imitate.ChromiumVersion/152", func(o *Options) { ChromiumVersion(o, 152) }},
		{"imitate.ChromiumVersion/153", func(o *Options) { ChromiumVersion(o, 153) }},
		{"imitate.ChromiumVersion/154", func(o *Options) { ChromiumVersion(o, 154) }},
		{"imitate.ChromiumVersion/155", func(o *Options) { ChromiumVersion(o, 155) }},
		{"imitate.ChromiumVersion/156", func(o *Options) { ChromiumVersion(o, 156) }},
		{"imitate.ChromiumVersion/157", func(o *Options) { ChromiumVersion(o, 157) }},
		{"imitate.ChromiumVersion/158", func(o *Options) { ChromiumVersion(o, 158) }},
		{"imitate.ChromiumVersion/159", func(o *Options) { ChromiumVersion(o, 159) }},
		{"imitate.ChromiumVersion/160", func(o *Options) { ChromiumVersion(o, 160) }},
		{"imitate.ChromiumVersion/161", func(o *Options) { ChromiumVersion(o, 161) }},
		{"imitate.Edge", Edge},
		{"imitate.Firefox144", Firefox144},
		{"imitate.Firefox147", Firefox147},
		{"imitate.Firefox148", Firefox148},
		{"imitate.Firefox151", Firefox151},
		{"imitate.Firefox158", Firefox158},
		{"imitate.Firefox", Firefox},
		{"imitate.FirefoxVersion/144", func(o *Options) { FirefoxVersion(o, 144) }},
		{"imitate.FirefoxVersion/147", func(o *Options) { FirefoxVersion(o, 147) }},
		{"imitate.FirefoxVersion/148", func(o *Options) { FirefoxVersion(o, 148) }},
		{"imitate.FirefoxVersion/150", func(o *Options) { FirefoxVersion(o, 150) }},
		{"imitate.FirefoxVersion/151", func(o *Options) { FirefoxVersion(o, 151) }},
		{"imitate.FirefoxVersion/157", func(o *Options) { FirefoxVersion(o, 157) }},
		{"imitate.FirefoxVersion/158", func(o *Options) { FirefoxVersion(o, 158) }},
		{"imitate.FirefoxVersion/160", func(o *Options) { FirefoxVersion(o, 160) }},
		{"imitate.Opera", Opera},
		{"imitate.Safari", Safari},
		{"ja4r.Chrome120JA4", snapshotJA4("Chrome120", Chrome120, 0)},
		{"ja4r.Chrome142JA4", snapshotJA4("Chrome142", Chrome142, 0)},
		{"ja4r.Chrome150JA4", snapshotJA4("Chrome150", Chrome150, 0)},
		{"ja4r.ChromeJA4", snapshotJA4("Chrome150", Chrome, 0)},
		{"ja4r.ChromiumJA4", snapshotJA4("Chrome150", Chromium, 0)},
		{"ja4r.EdgeJA4", snapshotJA4("Chrome150", Edge, 0)},
		{"ja4r.FirefoxJA4", snapshotJA4("Firefox158", Firefox158, 0)},
		{"ja4r.Firefox158JA4", snapshotJA4("Firefox158", Firefox158, 0)},
		{"ja4r.Firefox144JA4", snapshotJA4("Firefox158", Firefox158, 144)},
		{"ja4r.Firefox147JA4", snapshotJA4("Firefox158", Firefox158, 147)},
		{"ja4r.Firefox151JA4", snapshotJA4("Firefox158", Firefox158, 151)},
		{"ja4r.OperaJA4", snapshotJA4("Chrome150", Opera, 0)},
		{"ja4r.SafariJA4", snapshotJA4("Safari", Safari, 0)},
	}
}
