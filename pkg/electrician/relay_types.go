package electrician

import (
	"context"
	"time"
)

// RelayRequest is the byte-level publish/request envelope.
type RelayRequest struct {
	Topic   string
	Body    []byte
	Headers map[string]string
	Timeout time.Duration
}

// RelayClient is the minimal interface the router needs.
type RelayClient interface {
	Request(ctx context.Context, rr RelayRequest) ([]byte, error)
	Publish(ctx context.Context, rr RelayRequest) error
}
