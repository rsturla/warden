package tenant

import "testing"

func FuzzParseTenantConfig(f *testing.F) {
	f.Add([]byte(`
policies:
  - name: test
    host: "example.com"
    action: allow
secrets:
  - type: env
`))
	f.Add([]byte(`policies: []`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`
policies:
  - name: test
    host: "*.example.com"
    path: "/api/**"
    methods: ["GET", "POST"]
    action: allow
    inject:
      headers:
        Authorization: "Bearer ${TOKEN}"
      query:
        api_key: "${KEY}"
secrets:
  - type: vault
    address: https://vault.example.com:8200
    mount: secret
    prefix: app/
    auth: kubernetes
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseTenantConfig must not panic on any input
		_, _ = ParseTenantConfig(data)
	})
}
