package secrets

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestGCPServiceAccountSourceLiveADC(t *testing.T) {
	adcPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if adcPath == "" {
		adcPath = os.ExpandEnv("$HOME/.config/gcloud/application_default_credentials.json")
	}
	if _, err := os.Stat(adcPath); err != nil {
		t.Skip("no ADC credentials found, skipping live test")
	}

	src, err := NewGCPServiceAccountSource(GCPServiceAccountConfig{
		CredentialsFile: adcPath,
	})
	if err != nil {
		t.Fatalf("creating source: %v", err)
	}

	t.Logf("credential type: %s", src.credType)

	ctx := context.Background()
	token, ok, err := src.Resolve(ctx, "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if !ok {
		t.Fatal("expected token to be found")
	}
	if token == "" {
		t.Fatal("token is empty")
	}
	if !strings.HasPrefix(token, "ya29.") {
		t.Logf("warning: token doesn't start with ya29. prefix: %s...", token[:min(20, len(token))])
	}

	t.Logf("token obtained: %s...%s (%d chars)", token[:6], token[len(token)-4:], len(token))

	// Second resolve should use cache
	token2, ok2, err := src.Resolve(ctx, "GCP_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 {
		t.Fatal("cached resolve failed")
	}
	if token2 != token {
		t.Error("second resolve returned different token (cache miss)")
	}
}
