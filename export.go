package imitate

import (
	"context"
	"strings"

	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/imitate/internal/catalog"
)

// Export creates deterministic closed snapshots. Legacy random recipes become
// one explicitly frozen permitted realization; online Resolve retains its rules.
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
		if r.Legacy != nil && r.Legacy.Format == "ja3" {
			preset, err := catalog.LookupLegacy(r.Match.BaselineID)
			if err != nil {
				return profile.Bundle{}, err
			}
			extensions := ""
			if preset.RandomExtensions != nil {
				extensions = strings.Join(preset.RandomExtensions.Extensions, "-")
			}
			if strings.Contains(preset.Fingerprint, "<random-permutation;") {
				extensions = "0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65037-65281-41"
			}
			if extensions != "" {
				parts := strings.Split(r.Legacy.Hello, ",")
				parts[2] = extensions
				r.Legacy.Hello = strings.Join(parts, ",")
				r.Match.CompatibilityNotes = append(r.Match.CompatibilityNotes, "offline snapshot fixes one permitted legacy extension realization")
			}
		}
		if r.Spec != nil && r.Spec.Identity != nil {
			r.Match.UserAgent = r.Spec.Identity.UserAgent
		}
		b.Records = append(b.Records, r)
	}
	return b, nil
}
