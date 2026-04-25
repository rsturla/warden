package config

import "testing"

func FuzzConfigParse(f *testing.F) {
	f.Add([]byte(`policies: []`))
	f.Add([]byte(`
policies:
  - name: test
    host: "*.example.com"
    path: "/api/**"
    methods: ["GET"]
    action: allow
`))
	f.Add([]byte(`{{{`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input
		Parse(data)
	})
}
