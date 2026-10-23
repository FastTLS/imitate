package catalog

import (
	"errors"
	. "github.com/FastTLS/fastls/profile"
	"strings"
	"testing"
)

func TestBuiltinSelectorsAreFiniteAndIsolated(t *testing.T) {
	if builtinErr != nil {
		t.Fatal(builtinErr)
	}
	selections, err := ListBuiltinSelections()
	if err != nil {
		t.Fatal(err)
	}
	if len(selections) != 149 {
		t.Fatal("review recipe inventory")
	}
	for _, s := range selections {
		if len(s.Notes) == 0 {
			t.Fatal("legacy evidence limitations omitted")
		}
		got, err := LookupBuiltinSelection(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		got.Notes[0] = "mutated"
		next, _ := LookupBuiltinSelection(s.ID)
		if next.Notes[0] == "mutated" {
			t.Fatal("lookup leaked notes")
		}
	}
	selections[0].Notes[0] = "list mutation"
	next, _ := ListBuiltinSelections()
	if next[0].Notes[0] == "list mutation" {
		t.Fatal("list leaked notes")
	}
	bindings, err := ListLegacyBindings()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bindings {
		s, err := LookupBuiltinSelection(b.EntryPoint)
		if err != nil {
			t.Errorf("%s: %v", b.EntryPoint, err)
			continue
		}
		expected := b.Record
		// The parameterized FirefoxVersion inventory starts at its <158
		// baseline. Its no-argument selector alias uses the declared default.
		if b.EntryPoint == "imitate.FirefoxVersion" {
			expected = "Firefox158"
		}
		if s.Record != expected || s.Projection != b.Projection {
			t.Errorf("binding mismatch %s", b.EntryPoint)
		}
	}
	for _, name := range []string{"chrome149", "chrome161", "edge999", "chrome/156/android", "safari/18.7.3/macos", "library/net-http/1.26/windows/default", "chrome/156/windows/unknown"} {
		if _, err := LookupBuiltinSelection(name); !errors.Is(err, ErrUnknownProfile) {
			t.Errorf("invented selection %s", name)
		}
	}
	for _, alias := range builtinData.Aliases {
		s, err := LookupBuiltinSelection(" " + strings.ToUpper(alias.Name) + " ")
		if err != nil || s.ID != alias.Target {
			t.Errorf("invalid alias %s: %v", alias.Name, err)
		}
	}
}
