// core/types_registry.go
package core

import (
	"fmt"
	"reflect"

	"github.com/joeydtaylor/steeze-core/pkg/codec"
	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
)

// Register a concrete type to a symbolic name with a codec.
func RegisterType[T any](name string, c codec.Codec) error {
	if name == "" || c == nil {
		return fmt.Errorf("type name and codec required")
	}
	if _, ok := manifest.TypeReg[name]; ok {
		return fmt.Errorf("type %q already registered", name)
	}
	manifest.TypeReg[name] = manifest.TypeBinding{
		Name:  name,
		Codec: c,
		Zero:  func() any { var x T; return &x },
	}
	return nil
}

func MustRegisterType[T any](name string, c codec.Codec) {
	if err := RegisterType[T](name, c); err != nil {
		panic(err)
	}
}

func getTypeBinding(name string) (manifest.TypeBinding, bool) {
	b, ok := manifest.TypeReg[name]
	return b, ok
}

// ValidateAndCanonicalize asserts bytes decode into the registered type,
// then re-encodes canonically via the codec (round-trip).
func ValidateAndCanonicalize(typeName string, data []byte) (contentType string, out []byte, err error) {
	b, ok := getTypeBinding(typeName)
	if !ok {
		return "", nil, fmt.Errorf("unregistered type %q", typeName)
	}
	dst := b.Zero() // pointer to T
	if err := b.Codec.Unmarshal(data, dst); err != nil {
		return "", nil, fmt.Errorf("payload type %q invalid: %w", typeName, err)
	}
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return "", nil, fmt.Errorf("internal: zero() did not return pointer")
	}
	raw, err := b.Codec.Marshal(rv.Elem().Interface())
	if err != nil {
		return "", nil, fmt.Errorf("re-encode: %w", err)
	}
	return b.Codec.ContentType(), raw, nil
}

// add to file:

// GetTypeBinding exposes a safe view for internal packages.
func GetTypeBinding(name string) (struct {
	Name  string
	Codec codec.Codec
	Zero  func() any
}, bool) {
	b, ok := getTypeBinding(name)
	if !ok {
		return struct {
			Name  string
			Codec codec.Codec
			Zero  func() any
		}{}, false
	}
	return struct {
		Name  string
		Codec codec.Codec
		Zero  func() any
	}{Name: b.Name, Codec: b.Codec, Zero: b.Zero}, true
}

// FindTypeNameForValue helps transformer wrappers assert the registered type of T.
func FindTypeNameForValue[T any]() (string, bool) {
	// We can only map from registered names -> types; iterate once.
	for n, b := range manifest.TypeReg {
		// Compare types by creating a zero T and comparing its type to the registry’s zero.
		var t T
		if reflect.TypeOf(b.Zero()).Elem() == reflect.TypeOf(&t).Elem() {
			return n, true
		}
	}
	return "", false
}
