// Package client defines executable command-line client configurations.
package client

import (
	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/imitate/library"
)

func FastlsProbe() profile.Spec {
	s := library.FastlsPortable(false)
	s.ID = "client/fastls-probe/1/any/portable-h1"
	s.Metadata.Kind = "client"
	s.Metadata.Product = "fastls-probe"
	s.Metadata.ProductVersion = "1"
	s.Identity = &profile.Identity{UserAgent: "fastls-probe/1"}
	return s
}
