package secrets

import (
	"os"
	"testing"
)

func FuzzGCPServiceAccountLoadCredentials(f *testing.F) {
	f.Add([]byte(`{"type":"service_account","client_email":"a@b.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"}`))
	f.Add([]byte(`{"type":"authorized_user"}`))
	f.Add([]byte(`{"type":"external_account"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`{"type":"service_account"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := t.TempDir() + "/creds.json"
		if err := os.WriteFile(path, data, 0600); err != nil {
			return
		}
		NewGCPServiceAccountSource(GCPServiceAccountConfig{CredentialsFile: path})
	})
}

func FuzzGCPAuthorizedUserLoadCredentials(f *testing.F) {
	f.Add([]byte(`{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"}`))
	f.Add([]byte(`{"type":"service_account"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`{"type":"authorized_user"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := t.TempDir() + "/creds.json"
		if err := os.WriteFile(path, data, 0600); err != nil {
			return
		}
		NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{CredentialsFile: path})
	})
}
