// Package library defines named library configurations with explicit backend scope.
package library

import "github.com/FastTLS/fastls/profile"

// FastlsPortable is an official configurable Fastls baseline, not a claim to
// reproduce a third-party runtime. Its parameters are exercised on the wire.
func FastlsPortable(http2 bool) profile.Spec {
	variant := "portable-h1"
	alpn := []string{"http/1.1"}
	protocols := []string{"tls", "http1"}
	if http2 {
		variant = "portable-h2"
		alpn = []string{"h2", "http/1.1"}
		protocols = append(protocols, "http2")
	}
	s := profile.Spec{SchemaVersion: profile.SchemaVersion, ID: "library/fastls/2/any/" + variant,
		Metadata: profile.Metadata{Kind: "library", Family: "fastls", Product: "fastls", ProductVersion: "2", Platform: "any", Variant: variant, Implementation: "utls", ImplementationVersion: "1.8.1"},
		TLS: profile.TLSConfig{MinVersion: 0x0303, MaxVersion: 0x0304, CipherSuites: []profile.Code{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8}, ExtensionOrder: "fixed", SessionPolicy: "disabled", GREASEPolicy: "none",
			Extensions: []profile.Extension{{ID: 0}, {ID: 23}, {ID: 65281}, {ID: 10, Groups: []profile.Code{29, 23, 24}}, {ID: 11, PointFormats: []uint8{0}}, {ID: 13, SignatureAlgorithms: []profile.Code{0x0403, 0x0804, 0x0805, 0x0806, 0x0807, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601}}, {ID: 16, ALPN: alpn}, {ID: 43, Versions: []profile.Code{0x0304, 0x0303}}, {ID: 51, KeyShares: []profile.Code{29}}, {ID: 45, PSKModes: []uint8{1}}}},
		Headers:      profile.HeaderConfig{Defaults: []profile.Header{{Name: "Accept", Values: []string{"*/*"}}}, Order: []string{"host", "user-agent", "accept", "accept-encoding"}, PseudoOrder: []string{":method", ":authority", ":scheme", ":path"}},
		Capabilities: profile.Capabilities{Protocols: protocols, RequiredFeatures: []string{"tls.ordered.v1", "http1.ordered.v1"}, Limitations: []string{"official configurable baseline; no third-party client equivalence asserted"}},
		Evidence:     []profile.Evidence{{Source: "FastTLS/imitate official portable baseline; independent lab execution tests", VerifiedFields: []string{}}},
	}
	if http2 {
		s.HTTP2 = profile.HTTP2Config{Settings: []profile.Setting{{ID: 1, Value: 4096}, {ID: 2, Value: 0}, {ID: 4, Value: 1048576}, {ID: 6, Value: 65536}}, ConnectionFlow: 1048576}
		s.Capabilities.RequiredFeatures = append(s.Capabilities.RequiredFeatures, "http2.ordered.v1")
	}
	return s
}
