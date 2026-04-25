package policy

import (
	"context"
	"fmt"

	"github.com/rsturla/warden/internal/config"
)

type compiledRule struct {
	name      string
	hostMatch func(string) bool
	pathMatch func(string) bool
	methods   map[string]bool
	action    string
	inject    *InjectionDirective
}

type YAMLPolicyEngine struct {
	rules []compiledRule
}

func NewYAMLPolicyEngine(rules []config.PolicyRule) (*YAMLPolicyEngine, error) {
	compiled := make([]compiledRule, len(rules))
	for i, r := range rules {
		hostFn, err := CompileHostGlob(r.Host)
		if err != nil {
			return nil, fmt.Errorf("policy %q: host: %w", r.Name, err)
		}
		pathFn, err := CompilePathGlob(r.Path)
		if err != nil {
			return nil, fmt.Errorf("policy %q: path: %w", r.Name, err)
		}

		var methods map[string]bool
		if len(r.Methods) > 0 {
			methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				methods[m] = true
			}
		}

		var inject *InjectionDirective
		if r.Inject != nil {
			inject = &InjectionDirective{
				Headers: r.Inject.Headers,
				Query:   r.Inject.Query,
			}
		}

		compiled[i] = compiledRule{
			name:      r.Name,
			hostMatch: hostFn,
			pathMatch: pathFn,
			methods:   methods,
			action:    r.Action,
			inject:    inject,
		}
	}
	return &YAMLPolicyEngine{rules: compiled}, nil
}

func (e *YAMLPolicyEngine) Evaluate(_ context.Context, req *RequestContext) (*PolicyDecision, error) {
	for _, rule := range e.rules {
		if !rule.hostMatch(req.Host) {
			continue
		}
		if !rule.pathMatch(req.Path) {
			continue
		}
		if rule.methods != nil && !rule.methods[req.Method] {
			continue
		}

		if rule.action == "deny" {
			return &PolicyDecision{
				Allowed:  false,
				RuleName: rule.name,
				Reason:   "explicit_deny",
			}, nil
		}
		return &PolicyDecision{
			Allowed:  true,
			RuleName: rule.name,
			Inject:   rule.inject,
		}, nil
	}

	return &PolicyDecision{
		Allowed: false,
		Reason:  "no_match",
	}, nil
}

func (e *YAMLPolicyEngine) CanMatchHost(host string) bool {
	for _, rule := range e.rules {
		if rule.action == "allow" && rule.hostMatch(host) {
			return true
		}
	}
	return false
}
