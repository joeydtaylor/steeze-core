// pkg/electrician/sink_kafka.go
package electrician

import (
	"errors"
	"os"
	"strings"
	"time"
)

// kafkaEnv is pure-data config for Kafka writer.
type kafkaEnv struct {
	brokers         []string
	topic           string
	format          string // ndjson|json
	keyTemplate     string
	headers         map[string]string
	maxRecords      int
	maxBytes        int
	maxAge          time.Duration
	writerTimeoutMS int
	clientID        string
	// TLS
	tlsEnable   bool
	caFiles     []string
	serverName  string
	clientCert  string
	clientKey   string
	tlsInsecure bool
	// SASL
	saslMechanism string // SCRAM-SHA-256|SCRAM-SHA-512
	saslUsername  string
	saslPassword  string
}

func loadKafkaEnv() (*kafkaEnv, error) {
	cfg := &kafkaEnv{
		brokers:         splitCSV(os.Getenv("KAFKA_BROKERS")),
		topic:           strings.TrimSpace(os.Getenv("KAFKA_TOPIC")),
		format:          strings.ToLower(envOr("KAFKA_FORMAT", "ndjson")),
		keyTemplate:     os.Getenv("KAFKA_KEY_TEMPLATE"),
		headers:         parseKV(os.Getenv("KAFKA_HEADERS")),
		maxRecords:      coalesceInt(os.Getenv("KAFKA_BATCH_MAX_RECORDS"), 10000),
		maxBytes:        coalesceInt(os.Getenv("KAFKA_BATCH_MAX_BYTES_MB"), 16) * (1 << 20),
		maxAge:          coalesceDurMs(os.Getenv("KAFKA_BATCH_MAX_AGE_MS"), 800*time.Millisecond),
		writerTimeoutMS: envInt("KAFKA_WRITER_BATCH_TIMEOUT_MS", 400),
		clientID:        envOr("KAFKA_CLIENT_ID", "exodus-kafka-writer"),
		tlsEnable:       strings.EqualFold(os.Getenv("KAFKA_TLS_ENABLE"), "true") || os.Getenv("KAFKA_TLS_CA_FILES") != "",
		caFiles:         splitCSV(envOr("KAFKA_TLS_CA_FILES", "./tls/ca.crt,../tls/ca.crt,../../tls/ca.crt")),
		serverName:      envOr("KAFKA_TLS_SERVER_NAME", "localhost"),
		clientCert:      strings.TrimSpace(os.Getenv("KAFKA_TLS_CLIENT_CERT")),
		clientKey:       strings.TrimSpace(os.Getenv("KAFKA_TLS_CLIENT_KEY")),
		tlsInsecure:     strings.EqualFold(os.Getenv("KAFKA_TLS_INSECURE"), "true"),
		saslMechanism:   strings.ToUpper(strings.TrimSpace(os.Getenv("KAFKA_SASL_MECHANISM"))),
		saslUsername:    strings.TrimSpace(os.Getenv("KAFKA_SASL_USERNAME")),
		saslPassword:    strings.TrimSpace(os.Getenv("KAFKA_SASL_PASSWORD")),
	}
	if len(cfg.brokers) == 0 || cfg.topic == "" {
		return nil, nil // disabled
	}
	if cfg.format != "ndjson" && cfg.format != "json" {
		return nil, errors.New("kafka: KAFKA_FORMAT must be ndjson or json")
	}
	return cfg, nil
}
