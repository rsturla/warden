package secrets

import "context"

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
