package electrician

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

// typedPublisher implements a minimal typed publish surface with lazy builders.
// In server wiring, expose it to Fx as the expected interface via fx.As.
type typedPublisher struct {
	mu         sync.RWMutex
	submitters map[string]func(context.Context, any) error
}

// NewTypedPublisherFromEnv returns a publisher instance with lazy builders.
// If no targets are configured, it returns nil so the router falls back
// to byte-level publishing.
func NewTypedPublisherFromEnv() (*typedPublisher, error) {
	if strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET")) == "" {
		return nil, nil
	}
	return &typedPublisher{
		submitters: map[string]func(context.Context, any) error{},
	}, nil
}

// Publish uses (or lazily builds) a submitter for the given type.
func (tp *typedPublisher) Publish(ctx context.Context, topic, typeName string, v any, headers map[string]string) error {
	// Fast path?
	tp.mu.RLock()
	fn, ok := tp.submitters[typeName]
	tp.mu.RUnlock()
	if ok {
		return fn(ctx, v)
	}

	// Build lazily (Fx init-order safe)
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if fn2, ok2 := tp.submitters[typeName]; ok2 {
		return fn2(ctx, v)
	}
	mk := pubReg[typeName]
	if mk == nil {
		return fmt.Errorf("typed publisher: no submitter for %q", typeName)
	}
	sf, err := mk(ctx)
	if err != nil {
		return fmt.Errorf("typed publisher: build %q: %w", typeName, err)
	}
	if tp.submitters == nil {
		tp.submitters = map[string]func(context.Context, any) error{}
	}
	tp.submitters[typeName] = sf
	return sf(ctx, v)
}
