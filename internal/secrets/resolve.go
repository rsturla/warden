package secrets

import (
	"context"
	"fmt"
	"strings"
)

func ResolveTemplate(ctx context.Context, tmpl string, chain *Chain) (string, []string, error) {
	var resolved []string
	var result strings.Builder
	i := 0
	for i < len(tmpl) {
		if i+1 < len(tmpl) && tmpl[i] == '$' && tmpl[i+1] == '{' {
			end := strings.Index(tmpl[i:], "}")
			if end == -1 {
				return "", nil, fmt.Errorf("unclosed variable reference at position %d", i)
			}
			varName := tmpl[i+2 : i+end]
			if varName == "" {
				return "", nil, fmt.Errorf("empty variable name at position %d", i)
			}
			val, ok, err := chain.Resolve(ctx, varName)
			if err != nil {
				return "", nil, fmt.Errorf("resolving ${%s}: %w", varName, err)
			}
			if !ok {
				return "", nil, fmt.Errorf("secret ${%s} not found in any source", varName)
			}
			result.WriteString(val)
			resolved = append(resolved, varName)
			i += end + 1
		} else {
			result.WriteByte(tmpl[i])
			i++
		}
	}
	return result.String(), resolved, nil
}
