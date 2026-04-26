package secrets

import (
	"context"
	"time"
)

type Chain struct {
	sources []SecretSource
}

func NewChain(sources ...SecretSource) *Chain {
	return &Chain{sources: sources}
}

func (c *Chain) Resolve(ctx context.Context, name string) (string, bool, error) {
	for _, src := range c.sources {
		val, ok, err := src.Resolve(ctx, name)
		if err != nil {
			return "", false, err
		}
		if ok {
			return val, true, nil
		}
	}
	return "", false, nil
}

func (c *Chain) ResolveWithTTL(ctx context.Context, name string) (string, time.Duration, bool, error) {
	for _, src := range c.sources {
		val, ok, err := src.Resolve(ctx, name)
		if err != nil {
			return "", 0, false, err
		}
		if ok {
			if es, ok := src.(ExpiringSource); ok {
				return val, es.TokenTTL(), true, nil
			}
			return val, 0, true, nil
		}
	}
	return "", 0, false, nil
}
