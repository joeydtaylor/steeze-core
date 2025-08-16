// pkg/electrician/relay_noop.go
package electrician

import (
	"context"
	"fmt"
)

// noopRelay accepts publishes and discards them; Request is unsupported.
type noopRelay struct{}

func (noopRelay) Request(context.Context, RelayRequest) ([]byte, error) {
	return nil, fmt.Errorf("electrician(noop): request/reply unsupported")
}
func (noopRelay) Publish(context.Context, RelayRequest) error { return nil }
