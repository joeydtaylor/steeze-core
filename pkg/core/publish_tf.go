// pkg/core/publish_tf.go
package core

import (
	"fmt"
	"reflect"

	"github.com/joeydtaylor/steeze-core/pkg/core/transform"
)

// ApplyTransformsByName: bytes -> decode to registered T -> transformers -> re-encode via codec.
func ApplyTransformsByName(typeName string, names []string, payload []byte) ([]byte, error) {
	if typeName == "" || len(names) == 0 {
		return payload, nil
	}
	b, ok := getTypeBinding(typeName)
	if !ok {
		return nil, fmt.Errorf("unregistered type %q", typeName)
	}
	dst := b.Zero() // *T
	if err := b.Codec.Unmarshal(payload, dst); err != nil {
		return nil, fmt.Errorf("decode %q: %w", typeName, err)
	}
	val := reflect.ValueOf(dst).Elem().Interface() // T
	after, err := transform.ApplyDynamic(typeName, val, names)
	if err != nil {
		return nil, err
	}
	out, err := b.Codec.Marshal(after)
	if err != nil {
		return nil, fmt.Errorf("re-encode %q: %w", typeName, err)
	}
	return out, nil
}
