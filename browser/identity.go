// Package browser exposes the parameterized identity tools independently of HTTP.
package browser

import "github.com/FastTLS/imitate"

func ClientHints(version int, brand string) (string, error) {
	return imitate.GenerateSecChUa(version, brand)
}
func UserAgent(product string, version int, platform string) (string, error) {
	return imitate.GenerateChromiumUserAgent(product, version, platform)
}
