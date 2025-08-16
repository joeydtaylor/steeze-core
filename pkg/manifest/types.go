package manifest

import "github.com/joeydtaylor/steeze-core/pkg/codec"

// HandlerType enumerates the supported handler kinds.
type HandlerType string

// TypeBinding ties a symbolic datatype name to its codec and zero-value constructor.
// Other packages (core/types_registry.go) populate TypeReg.
type TypeBinding struct {
	Name  string
	Codec codec.Codec
	Zero  func() any
}

// TypeReg: register datatypes by name (used to validate RelaySpec.DataType and pipelines).
var TypeReg = make(map[string]TypeBinding)

const (
	HandlerInproc       HandlerType = "inproc"
	HandlerRelayReq     HandlerType = "relay.request"
	HandlerRelayPublish HandlerType = "relay.publish"
	HandlerProxy        HandlerType = "proxy"
)
