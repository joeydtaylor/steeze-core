package manifest

// SinkType enumerates sink backends.
type SinkType string

const (
	SinkTypeS3    SinkType = "s3"
	SinkTypeKafka SinkType = "kafka"
)

// Sink fans in from produced wires into a backend (S3/Kafka/...).
type Sink struct {
	Type   SinkType   `toml:"type"`            // "s3" | "kafka"
	Name   string     `toml:"name"`            // optional, for logging/metrics
	Inputs []string   `toml:"inputs"`          // wires to fan-in (must match ReceiverPipeline.output)
	S3     *S3Sink    `toml:"s3,omitempty"`    // for type == "s3"
	Kafka  *KafkaSink `toml:"kafka,omitempty"` // for type == "kafka"
}
