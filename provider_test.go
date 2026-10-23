package imitate_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/imitate"
)

func TestCanonicalCatalogAndBrandGeneration(t *testing.T) {
	p := imitate.New()
	for _, id := range []string{"chrome156-win", "chrome/windows/156", "chrome/156/windows/compat-v1", "chrome"} {
		if _, err := p.Resolve(context.Background(), profile.ResolveRequest{Selector: id}); !errors.Is(err, profile.ErrUnknownProfile) {
			t.Fatal(id, err)
		}
	}
	b, err := os.ReadFile("testdata/consumer-options.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct{ Brands map[string]string }
	if err = json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Brands) != 244 {
		t.Fatal(len(data.Brands))
	}
	for key, want := range data.Brands {
		v, brand, _ := strings.Cut(key, "/")
		n, _ := strconv.Atoi(v)
		got, err := imitate.GenerateSecChUa(n, brand)
		if err != nil || got != want {
			t.Fatal(key, got, err)
		}
	}
	ua := "Firefox/151.0"
	r, err := p.Resolve(context.Background(), profile.ResolveRequest{Selector: "chrome/156/windows", UserAgent: &ua})
	if err != nil || r.Match.Product != "chrome" || !strings.Contains(r.Legacy.UserAgent, "Chrome/156.") {
		t.Fatal(r.Match, err)
	}
}
func TestFiniteRangeCancellationAndIndependentOwnership(t *testing.T) {
	p := imitate.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Resolve(ctx, profile.ResolveRequest{Selector: "chrome"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, id := range []string{"chrome/999/windows", "library/curl/999/any/default", "client/unknown/1/any/default"} {
		if _, err := p.Resolve(context.Background(), profile.ResolveRequest{Selector: id}); !errors.Is(err, profile.ErrUnknownProfile) {
			t.Fatal(id, err)
		}
	}
	ids, err := p.List()
	if err != nil || len(ids) != 152 {
		t.Fatal(len(ids), err)
	}
	r, err := p.Resolve(context.Background(), profile.ResolveRequest{Selector: "chrome/155/windows"})
	if err != nil {
		t.Fatal(err)
	}
	r.Headers.Rules[0].Values[0] = "changed"
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := p.Resolve(context.Background(), profile.ResolveRequest{Selector: "chrome/155/windows"})
			if err != nil {
				t.Error(err)
				return
			}
			for _, h := range r.Headers.Rules {
				if strings.Contains(strings.Join(h.Values, ""), "changed") {
					t.Error("shared mutable output")
				}
			}
		}()
	}
	wg.Wait()
}
