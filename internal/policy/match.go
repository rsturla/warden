package policy

import (
	"fmt"
	"strings"
)

func CompileHostGlob(pattern string) (func(string) bool, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty host pattern")
	}
	lower := strings.ToLower(pattern)

	if !strings.Contains(lower, "*") {
		return func(host string) bool {
			return strings.ToLower(host) == lower
		}, nil
	}

	parts := strings.Split(lower, ".")
	return func(host string) bool {
		hostParts := strings.Split(strings.ToLower(host), ".")
		if len(hostParts) != len(parts) {
			return false
		}
		for i, p := range parts {
			if p == "*" {
				continue
			}
			if hostParts[i] != p {
				return false
			}
		}
		return true
	}, nil
}

func CompilePathGlob(pattern string) (func(string) bool, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty path pattern")
	}
	if pattern == "/**" {
		return func(string) bool { return true }, nil
	}

	parts := splitPath(pattern)
	return func(path string) bool {
		return matchPath(parts, splitPath(path))
	}, nil
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func matchPath(pattern, path []string) bool {
	pi, pa := 0, 0
	for pi < len(pattern) && pa < len(path) {
		seg := pattern[pi]
		switch seg {
		case "**":
			if pi == len(pattern)-1 {
				return true
			}
			for try := pa; try <= len(path); try++ {
				if matchPath(pattern[pi+1:], path[try:]) {
					return true
				}
			}
			return false
		case "*":
			pi++
			pa++
		default:
			if path[pa] != seg {
				return false
			}
			pi++
			pa++
		}
	}

	// Remaining pattern segments must all be ** to match
	for pi < len(pattern) {
		if pattern[pi] != "**" {
			return false
		}
		pi++
	}
	return pa == len(path)
}
