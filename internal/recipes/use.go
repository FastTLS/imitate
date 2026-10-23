package recipes

import (
	"fmt"
	"github.com/FastTLS/fastls/profile"
	frozen "github.com/FastTLS/imitate/internal/catalog"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
)

type useConfig struct {
	ua       string
	uaSet    bool
	defaults profile.Defaults
	policy   profile.MatchPolicy
}
type UseOption func(*useConfig)

func WithUserAgent(ua string) UseOption          { return func(c *useConfig) { c.ua = ua; c.uaSet = true } }
func WithDefaults(d profile.Defaults) UseOption  { return func(c *useConfig) { c.defaults = d } }
func WithPolicy(p profile.MatchPolicy) UseOption { return func(c *useConfig) { c.policy = p } }

// Select the declared protocol recipe. Request headers are applied by the caller.
func Use(options *Options, selector string, opts ...UseOption) (profile.Match, error) {
	if options == nil {
		return profile.Match{}, profile.ErrInvalidOptions
	}
	c := useConfig{policy: profile.AllowCompatible}
	for _, option := range opts {
		if option == nil {
			return profile.Match{}, profile.ErrInvalidOptions
		}
		option(&c)
	}
	if c.policy != profile.RecordedOnly && c.policy != profile.AllowCompatible {
		return profile.Match{}, profile.ErrInvalidOptions
	}
	if selector == "" {
		selector = c.defaults.Selector
	}
	work := Options{}
	m, err := useBuiltin(&work, selector, "", c)
	if err != nil {
		return profile.Match{}, err
	}
	if err = normalizeHeaders(&work, false); err != nil {
		return profile.Match{}, err
	}
	work.Headers["User-Agent"] = work.UserAgent
	m.Selector = selector
	m.UserAgent = work.UserAgent
	*options = work
	return m, nil
}

func normalizeHeaders(o *Options, overrideUA bool) error {
	keys := make([]string, 0, len(o.Headers))
	for key := range o.Headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if key == "" || strings.IndexFunc(key, func(r rune) bool {
			return r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
		}) >= 0 {
			return fmt.Errorf("%w: invalid header name", profile.ErrInvalidOptions)
		}
		v := o.Headers[key]
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: invalid header value", profile.ErrInvalidOptions)
		}
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		if overrideUA && canonical == "User-Agent" {
			continue
		}
		if old, ok := result[canonical]; ok && old != v {
			return fmt.Errorf("%w: conflicting duplicate header %s", profile.ErrInvalidOptions, canonical)
		}
		result[canonical] = v
	}
	o.Headers = result
	return nil
}

func useBuiltin(o *Options, selector, ua string, c useConfig) (profile.Match, error) {
	s, err := frozen.LookupBuiltinSelection(selector)
	if err != nil {
		return profile.Match{}, err
	}
	if s.ID != selector {
		return profile.Match{}, fmt.Errorf("%w: canonical profile ID required", profile.ErrUnknownProfile)
	}
	if s.Compatible && c.policy == profile.RecordedOnly {
		return profile.Match{}, profile.ErrUnknownProfile
	}
	p, err := frozen.LookupLegacy(s.Record)
	if err != nil {
		return profile.Match{}, err
	}
	removeClientHints(o.Headers)
	// Translate the normalized map to legacy spellings before the old applier,
	// so its overwrite/if-empty decisions still apply case-insensitively.
	for _, h := range p.Headers {
		canonical := textproto.CanonicalMIMEHeaderKey(h.Name)
		if canonical != h.Name {
			if v, ok := o.Headers[canonical]; ok {
				delete(o.Headers, canonical)
				o.Headers[h.Name] = v
			}
		}
	}
	applyLegacy(o, s.Record, p.HTTP2Settings)
	if s.Identity == "chromium" {
		major, _ := strconv.Atoi(s.Version)
		applySelectedChromiumIdentity(o, s.Product, major, platformShort(s.Platform))
	} else if s.Identity == "firefox" {
		major, _ := strconv.Atoi(s.Version)
		setFirefoxUA(o, major)
		if s.Platform == "linux" {
			o.UserAgent = strings.Replace(o.UserAgent, "Windows NT 10.0; Win64; x64", "X11; Linux x86_64", 1)
		}
		if s.Platform == "macos" {
			o.UserAgent = strings.Replace(o.UserAgent, "Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10.15", 1)
		}
	} else if s.Identity == "opera" {
		major, _ := strconv.Atoi(s.EngineVersion)
		o.UserAgent = GenerateChromiumUserAgent("chrome", major, "win") + " OPR/" + s.Version + ".0.0.0"
		o.Headers["Sec-Ch-Ua"] = GenerateSecChUa(major, "Opera")
	}
	if ua != "" {
		o.UserAgent = ua
	}
	if s.Product == "edge" && o.Headers["Accept"] == pHeader(p, "Accept") {
		o.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}
	if s.Product == "firefox" || s.Product == "safari" {
		removeClientHints(o.Headers)
	}
	if s.Projection == "ja4r" {
		v, err := frozen.LegacyJA4R(s.Record)
		if err != nil {
			return profile.Match{}, err
		}
		o.Fingerprint = Ja4Fingerprint{FingerprintValue: v}
	}
	method := "recorded"
	if s.Compatible {
		method = "compatible"
	}
	engine := s.EngineVersion
	if engine == "" && (s.Product == "chrome" || s.Product == "chromium") {
		engine = s.Version
	}
	return profile.Match{ProfileID: s.ID, Kind: "browser", Product: s.Product, ProductVersion: s.Version, EngineVersion: engine, Platform: s.Platform, Device: p.Metadata.Device, BaselineID: s.Record, Method: method, VerifiedFields: slices.Clone(p.VerifiedFields), CompatibilityNotes: slices.Clone(s.Notes), Source: p.Source}, nil
}

func applySelectedChromiumIdentity(o *Options, product string, major int, platform string) {
	brand := "Google Chrome"
	if product == "edge" {
		brand = "Microsoft Edge"
	}
	if product == "chromium" {
		brand = ""
	}
	o.Headers["Sec-Ch-Ua"] = GenerateSecChUa(major, brand)
	o.Headers["Sec-Ch-Ua-Mobile"] = "?0"
	o.Headers["Sec-Ch-Ua-Platform"] = secChUaPlatform[platform]
	o.UserAgent = GenerateChromiumUserAgent(product, major, platform)
}

func pHeader(p frozen.LegacyPreset, key string) string {
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, key) {
			return h.Value
		}
	}
	return ""
}
func removeClientHints(headers map[string]string) {
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "sec-ch-ua") {
			delete(headers, key)
		}
	}
}
