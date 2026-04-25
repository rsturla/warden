package ca

import "testing"

func FuzzGetOrCreateCert(f *testing.F) {
	f.Add("api.github.com")
	f.Add("example.com")
	f.Add("127.0.0.1")
	f.Add("::1")
	f.Add("")
	f.Add("*.example.com")
	f.Add("a.b.c.d.e.f.g")

	c, err := NewAutoCA("")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, host string) {
		if host == "" {
			return
		}
		c.GetOrCreateCert(host)
	})
}
