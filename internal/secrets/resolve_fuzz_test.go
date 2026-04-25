package secrets

import "testing"

func FuzzResolveTemplate(f *testing.F) {
	f.Add("${TOKEN}")
	f.Add("Bearer ${TOKEN}")
	f.Add("static-value")
	f.Add("${A}-${B}")
	f.Add("${}")
	f.Add("${UNCLOSED")
	f.Add("")
	f.Add("$$${x}")
	f.Add("no vars here")

	chain := NewChain(&stubSource{"fuzz", map[string]string{
		"TOKEN": "val",
		"A":     "1",
		"B":     "2",
		"x":     "3",
	}})

	f.Fuzz(func(t *testing.T, tmpl string) {
		ResolveTemplate(t.Context(), tmpl, chain)
	})
}
