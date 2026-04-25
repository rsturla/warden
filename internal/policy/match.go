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

	parts := collapseDoubleStars(splitPath(pattern))
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

// collapseDoubleStars deduplicates consecutive "**" segments to prevent
// exponential backtracking — consecutive ** are semantically identical to one.
func collapseDoubleStars(parts []string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "**" && len(out) > 0 && out[len(out)-1] == "**" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func matchPath(pattern, path []string) bool {
	stars := 0
	for _, s := range pattern {
		if s == "**" {
			stars++
		}
	}
	if stars <= 1 {
		return matchPathIter(pattern, path, 0, 0)
	}
	return matchPathMemo(pattern, path, 0, 0, make(map[[2]int]bool))
}

func matchPathIter(pattern, path []string, pi, pa int) bool {
	for pi < len(pattern) && pa < len(path) {
		switch pattern[pi] {
		case "**":
			if pi == len(pattern)-1 {
				return true
			}
			for try := pa; try <= len(path); try++ {
				if matchPathIter(pattern, path, pi+1, try) {
					return true
				}
			}
			return false
		case "*":
			pi++
			pa++
		default:
			if path[pa] != pattern[pi] {
				return false
			}
			pi++
			pa++
		}
	}
	for pi < len(pattern) {
		if pattern[pi] != "**" {
			return false
		}
		pi++
	}
	return pa == len(path)
}

func matchPathMemo(pattern, path []string, pi, pa int, memo map[[2]int]bool) bool {
	for pi < len(pattern) && pa < len(path) {
		switch pattern[pi] {
		case "**":
			if pi == len(pattern)-1 {
				return true
			}
			for try := pa; try <= len(path); try++ {
				k := [2]int{pi + 1, try}
				if v, ok := memo[k]; ok {
					if v {
						return true
					}
					continue
				}
				result := matchPathMemo(pattern, path, pi+1, try, memo)
				memo[k] = result
				if result {
					return true
				}
			}
			return false
		case "*":
			pi++
			pa++
		default:
			if path[pa] != pattern[pi] {
				return false
			}
			pi++
			pa++
		}
	}
	for pi < len(pattern) {
		if pattern[pi] != "**" {
			return false
		}
		pi++
	}
	return pa == len(path)
}
