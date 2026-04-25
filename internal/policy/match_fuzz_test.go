package policy

import "testing"

func FuzzCompilePathGlob(f *testing.F) {
	f.Add("/**")
	f.Add("/repos/*/pulls")
	f.Add("/repos/**/issues")
	f.Add("/a/b/c")
	f.Add("")
	f.Add("/*")

	f.Fuzz(func(t *testing.T, pattern string) {
		CompilePathGlob(pattern)
	})
}

func FuzzPathMatch(f *testing.F) {
	f.Add("/**", "/foo/bar")
	f.Add("/repos/*/pulls", "/repos/myorg/pulls")
	f.Add("/a/**/b", "/a/x/y/z/b")
	f.Add("/*", "/hello")

	f.Fuzz(func(t *testing.T, pattern, path string) {
		fn, err := CompilePathGlob(pattern)
		if err != nil {
			return
		}
		fn(path)
	})
}

func FuzzCompileHostGlob(f *testing.F) {
	f.Add("api.github.com")
	f.Add("*.example.com")
	f.Add("")

	f.Fuzz(func(t *testing.T, pattern string) {
		CompileHostGlob(pattern)
	})
}

func FuzzHostMatch(f *testing.F) {
	f.Add("*.example.com", "api.example.com")
	f.Add("api.github.com", "api.github.com")
	f.Add("*.example.com", "evil.com")

	f.Fuzz(func(t *testing.T, pattern, host string) {
		fn, err := CompileHostGlob(pattern)
		if err != nil {
			return
		}
		fn(host)
	})
}
