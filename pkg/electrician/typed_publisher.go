// pkg/electrician/typed_publisher.go
package electrician

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

// typedPublisher provides lazy-built submitters per datatype.
type typedPublisher struct {
	mu         sync.RWMutex
	submitters map[string]func(context.Context, any) error
}

// Publish uses (or lazily builds) a submitter for the given type.
// Note: topic and headers are intentionally unused (matches existing behavior).
func (tp *typedPublisher) Publish(ctx context.Context, topic, typeName string, v any, headers map[string]string) error {
	tp.mu.RLock()
	fn, ok := tp.submitters[typeName]
	tp.mu.RUnlock()
	if ok {
		return fn(ctx, v)
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()
	if fn2, ok2 := tp.submitters[typeName]; ok2 {
		return fn2(ctx, v)
	}
	mk, ok := pubReg[typeName]
	if !ok || mk == nil {
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

// NewTypedPublisherFromEnv returns a publisher instance with lazy builders.
// Returns nil when ELECTRICIAN_TARGET is unset (no-op mode), matching previous behavior.
func NewTypedPublisherFromEnv() (*typedPublisher, error) {
	if strings.TrimSpace(os.Getenv("ELECTRICIAN_TARGET")) == "" {
		return nil, nil
	}
	return &typedPublisher{
		submitters: map[string]func(context.Context, any) error{},
	}, nil
}
