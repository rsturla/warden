package policy

import "testing"

func TestCompileHostGlob(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Exact match
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "API.GITHUB.COM", true}, // case insensitive
		{"api.github.com", "evil.com", false},
		{"api.github.com", "api.github.com.evil.com", false},

		// Wildcard subdomain
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "ADMIN.EXAMPLE.COM", true},    // case insensitive
		{"*.example.com", "example.com", false},         // no subdomain
		{"*.example.com", "sub.api.example.com", false}, // nested subdomain

		// Wildcard with multiple levels
		{"*.*.example.com", "a.b.example.com", true},
		{"*.*.example.com", "a.example.com", false},
	}

	for _, tt := range tests {
		fn, err := CompileHostGlob(tt.pattern)
		if err != nil {
			t.Errorf("CompileHostGlob(%q): %v", tt.pattern, err)
			continue
		}
		got := fn(tt.host)
		if got != tt.want {
			t.Errorf("pattern=%q host=%q: got %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestCompileHostGlobMiddleWildcard(t *testing.T) {
	// example.*.com should match example.foo.com
	fn, err := CompileHostGlob("example.*.com")
	if err != nil {
		t.Fatalf("CompileHostGlob: %v", err)
	}
	if !fn("example.foo.com") {
		t.Error("should match example.foo.com")
	}
	if fn("example.com") {
		t.Error("should not match example.com")
	}
}

func TestCompileHostGlobErrors(t *testing.T) {
	_, err := CompileHostGlob("")
	if err == nil {
		t.Error("expected error for empty pattern")
	}
}

func TestCompilePathGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Match all
		{"/**", "/anything", true},
		{"/**", "/a/b/c/d", true},
		{"/**", "/", true},

		// Exact path
		{"/foo", "/foo", true},
		{"/foo", "/foo/bar", false},
		{"/foo", "/bar", false},

		// Single wildcard
		{"/repos/*/pulls", "/repos/myorg/pulls", true},
		{"/repos/*/pulls", "/repos/other/pulls", true},
		{"/repos/*/pulls", "/repos/myorg/sub/pulls", false}, // * = one segment
		{"/repos/*/pulls", "/repos/pulls", false},           // missing segment

		// Double wildcard
		{"/repos/**", "/repos/a", true},
		{"/repos/**", "/repos/a/b/c", true},
		{"/repos/**", "/repos/", true},
		{"/repos/**", "/other", false},

		// Mixed
		{"/repos/*/issues/**", "/repos/myorg/issues/123/comments", true},
		{"/repos/*/issues/**", "/repos/myorg/issues", true},
		{"/repos/*/issues/**", "/repos/myorg/pulls", false},

		// Double wildcard at start
		{"/**/pulls", "/repos/myorg/pulls", true},
		{"/**/pulls", "/pulls", true},

		// Multiple segments
		{"/a/b/c", "/a/b/c", true},
		{"/a/b/c", "/a/b/d", false},
		{"/a/b/c", "/a/b", false},
		{"/a/b/c", "/a/b/c/d", false},
	}

	for _, tt := range tests {
		fn, err := CompilePathGlob(tt.pattern)
		if err != nil {
			t.Errorf("CompilePathGlob(%q): %v", tt.pattern, err)
			continue
		}
		got := fn(tt.path)
		if got != tt.want {
			t.Errorf("pattern=%q path=%q: got %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestCompilePathGlobEdgeCases(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Trailing slash
		{"/api/", "/api/", true},
		{"/api", "/api/", false},

		// Root path
		{"/**", "/", true},
		{"/", "/", true},
		{"/", "/foo", false},

		// Double wildcard at different positions
		{"/**/comments", "/repos/org/issues/123/comments", true},
		{"/**/comments", "/comments", true},
		{"/a/**/z", "/a/z", true},
		{"/a/**/z", "/a/b/c/z", true},

		// Empty path
		{"/**", "", true},

		// Wildcard only
		{"/*", "/foo", true},
		{"/*", "/", false},
	}

	for _, tt := range tests {
		fn, err := CompilePathGlob(tt.pattern)
		if err != nil {
			t.Errorf("CompilePathGlob(%q): %v", tt.pattern, err)
			continue
		}
		got := fn(tt.path)
		if got != tt.want {
			t.Errorf("pattern=%q path=%q: got %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestCompilePathGlobErrors(t *testing.T) {
	_, err := CompilePathGlob("")
	if err == nil {
		t.Error("expected error for empty pattern")
	}
}
