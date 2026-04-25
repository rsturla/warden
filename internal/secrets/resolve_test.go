package secrets

import (
	"context"
	"testing"
)

func testChain() *Chain {
	return NewChain(&stubSource{"test", map[string]string{
		"TOKEN":   "ghp_abc123",
		"API_KEY": "key-456",
	}})
}

func TestResolveTemplateSingleVar(t *testing.T) {
	val, names, err := ResolveTemplate(context.Background(), "${TOKEN}", testChain())
	if err != nil {
		t.Fatal(err)
	}
	if val != "ghp_abc123" {
		t.Errorf("val = %q", val)
	}
	if len(names) != 1 || names[0] != "TOKEN" {
		t.Errorf("names = %v", names)
	}
}

func TestResolveTemplateWithPrefix(t *testing.T) {
	val, names, err := ResolveTemplate(context.Background(), "Bearer ${TOKEN}", testChain())
	if err != nil {
		t.Fatal(err)
	}
	if val != "Bearer ghp_abc123" {
		t.Errorf("val = %q", val)
	}
	if len(names) != 1 {
		t.Errorf("names = %v", names)
	}
}

func TestResolveTemplateMultipleVars(t *testing.T) {
	val, names, err := ResolveTemplate(context.Background(), "${TOKEN}-${API_KEY}", testChain())
	if err != nil {
		t.Fatal(err)
	}
	if val != "ghp_abc123-key-456" {
		t.Errorf("val = %q", val)
	}
	if len(names) != 2 {
		t.Errorf("names = %v", names)
	}
}

func TestResolveTemplateStatic(t *testing.T) {
	val, names, err := ResolveTemplate(context.Background(), "static-value", testChain())
	if err != nil {
		t.Fatal(err)
	}
	if val != "static-value" {
		t.Errorf("val = %q", val)
	}
	if names != nil {
		t.Errorf("names should be nil for static, got %v", names)
	}
}

func TestResolveTemplateMissing(t *testing.T) {
	_, _, err := ResolveTemplate(context.Background(), "${MISSING}", testChain())
	if err == nil {
		t.Error("expected error for missing var")
	}
}

func TestResolveTemplateUnclosed(t *testing.T) {
	_, _, err := ResolveTemplate(context.Background(), "${UNCLOSED", testChain())
	if err == nil {
		t.Error("expected error for unclosed var")
	}
}

func TestResolveTemplateEmptyVarName(t *testing.T) {
	_, _, err := ResolveTemplate(context.Background(), "${}", testChain())
	if err == nil {
		t.Error("expected error for empty var name")
	}
}

func TestResolveTemplateEmpty(t *testing.T) {
	val, names, err := ResolveTemplate(context.Background(), "", testChain())
	if err != nil {
		t.Fatal(err)
	}
	if val != "" {
		t.Errorf("val = %q", val)
	}
	if names != nil {
		t.Errorf("names = %v", names)
	}
}
