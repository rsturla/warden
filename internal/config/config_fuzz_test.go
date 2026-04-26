package config_test

import (
	"testing"

	"github.com/rsturla/warden/internal/config"
	_ "github.com/rsturla/warden/internal/secrets"
)

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
		config.Parse(data)
	})
}
