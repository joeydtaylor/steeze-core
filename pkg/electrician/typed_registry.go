// pkg/electrician/typed_registry.go
package electrician

import (
	"context"
	"fmt"
	"sync"

	"github.com/joeydtaylor/steeze-core/pkg/core/transform"
)

// Registries.
var (
	mu     sync.RWMutex
	pubReg = map[string]func(ctx context.Context) (func(context.Context, any) error, error){}
	rcvReg = map[string]func(ctx context.Context, address string, buffer int, names []string) (func(), error){}
)

// EnableBuilderType registers:
//   - a typed publisher factory for T
//   - a receiver starter (by datatype name) that resolves manifest transformer names
func EnableBuilderType[T any](typeName string) {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := pubReg[typeName]; !exists {
		pubReg[typeName] = func(ctx context.Context) (func(context.Context, any) error, error) {
			return buildTypedForwardSubmitter[T](ctx, typeName)
		}
	}

	if _, exists := rcvReg[typeName]; !exists {
		rcvReg[typeName] = func(ctx context.Context, address string, buffer int, names []string) (func(), error) {
			tfs, err := transform.Resolve[T](typeName, names)
			if err != nil {
				return nil, err
			}
			fns := make([]func(T) (T, error), len(tfs))
			for i := range tfs {
				tf := tfs[i]
				fns[i] = func(v T) (T, error) { return tf(v) }
			}
			return StartReceiverForwardFromEnv[T](ctx, address, buffer, fns...)
		}
	}
}

// StartReceiverForwardFromEnvByName is used by server.go to start receivers generically.
func StartReceiverForwardFromEnvByName(
	ctx context.Context,
	address string,
	buffer int,
	datatype string,
	transformerNames []string,
) (func(), error) {
	mu.RLock()
	mk, ok := rcvReg[datatype]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("datatype not enabled: %s", datatype)
	}
	return mk(ctx, address, buffer, transformerNames)
}
