package imitate

import (
	"context"

	"github.com/FastTLS/fastls/profile"
)

// Export creates deterministic closed full-Spec snapshots. Per-connection
// generation strategies remain explicit data, just as in online Resolve.
func (p *Provider) Export(ctx context.Context) (profile.Bundle, error) {
	b := profile.Bundle{SchemaVersion: profile.SchemaVersion, ProviderID: "FastTLS/imitate.snapshot", ProviderVersion: Version, DataRevision: DataRevision}
	ids, err := p.List()
	if err != nil {
		return b, err
	}
	b.Aliases = nil
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return profile.Bundle{}, err
		}
		r, err := p.Resolve(ctx, profile.ResolveRequest{Selector: id})
		if err != nil {
			return profile.Bundle{}, err
		}
		if r.Spec != nil && r.Spec.Identity != nil {
			r.Match.UserAgent = r.Spec.Identity.UserAgent
		}
		b.Records = append(b.Records, r)
	}
	return b, nil
}
