package electrician

import (
	"context"
	"fmt"
	"sync"
)

type builderClient struct {
	once   sync.Once
	start  error
	submit func(context.Context, []byte) error // captures wire.Submit
}

// Request is unsupported in builder mode (stream/publish only).
func (c *builderClient) Request(ctx context.Context, rr RelayRequest) ([]byte, error) {
	return nil, fmt.Errorf("electrician(builder): request/reply unsupported")
}

// Publish sends bytes into the pipeline. Topic/headers ride the relay path.
func (c *builderClient) Publish(ctx context.Context, rr RelayRequest) error {
	if rr.Topic == "" {
		return fmt.Errorf("relay: missing topic")
	}
	if c.start != nil {
		return c.start
	}
	return c.submit(ctx, rr.Body)
}
