package inject

import (
	"net/http"
	"testing"

	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
)

func FuzzInjectHeaders(f *testing.F) {
	f.Add("Authorization", "Bearer ${TOKEN}")
	f.Add("X-Custom", "static-value")
	f.Add("X-Test", "${API_KEY}")
	f.Add("", "")

	ch := secrets.NewChain(&stubSource{map[string]string{
		"TOKEN":   "val",
		"API_KEY": "key",
	}})

	f.Fuzz(func(t *testing.T, name, value string) {
		req, err := http.NewRequest("GET", "https://example.com/", nil)
		if err != nil {
			return
		}
		Apply(t.Context(), req, &policy.InjectionDirective{
			Headers: map[string]string{name: value},
		}, ch)
	})
}
