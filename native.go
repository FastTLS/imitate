package imitate

import (
	"context"
	"fmt"
	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/imitate/client"
	"github.com/FastTLS/imitate/library"
)

var nativeIDs = []string{"library/fastls/2/any/portable-h1", "library/fastls/2/any/portable-h2", "client/fastls-probe/1/any/portable-h1"}

func resolveNative(ctx context.Context, r profile.ResolveRequest) (profile.Resolution, error) {
	if err := ctx.Err(); err != nil {
		return profile.Resolution{}, err
	}
	var s profile.Spec
	switch r.Selector {
	case nativeIDs[0]:
		s = library.FastlsPortable(false)
	case nativeIDs[1]:
		s = library.FastlsPortable(true)
	case nativeIDs[2]:
		s = client.FastlsProbe()
	default:
		return profile.Resolution{}, fmt.Errorf("%w: %s", profile.ErrUnknownProfile, r.Selector)
	}
	if r.Policy == profile.RecordedOnly {
		return profile.Resolution{}, fmt.Errorf("%w: portable baseline has no third-party observation", profile.ErrUnknownProfile)
	}
	if r.Policy != "" && r.Policy != profile.AllowCompatible {
		return profile.Resolution{}, profile.ErrInvalidOptions
	}
	if err := profile.Validate(s); err != nil {
		return profile.Resolution{}, err
	}
	ua := ""
	if s.Identity != nil {
		ua = s.Identity.UserAgent
	}
	return profile.Resolution{Spec: &s, Match: profile.Match{ProfileID: s.ID, UserAgent: ua, Selector: r.Selector, Kind: s.Metadata.Kind, Product: s.Metadata.Product, ProductVersion: s.Metadata.ProductVersion, Platform: s.Metadata.Platform, Method: "configured", ProviderID: "FastTLS/imitate", ProviderVersion: Version, DataRevision: DataRevision, ContractVersion: profile.ContractVersion}}, nil
}
