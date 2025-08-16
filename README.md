# steeze-core ⚡️🧠

**Manifest‑driven core for typed pipelines, HTTP servers, and cloud relays**

<p align="center">
  <em>One runtime, many services — wire once, ship everywhere.</em>
</p>

---

## ✨ Highlights

* 🧩 **Manifest routing** — declarative TOML for routes + pipelines.
* 🔐 **Secure defaults** — TLS 1.3 where applicable, structured logs, no secret echo.
* 📈 **Observability** — logger + metrics middleware pre‑wired.
* ⚡ **Electrician integration** — typed publisher, byte relay, receiver→wire→sinks (S3/Kafka).
* 🧱 **Composability** — add AWS/Azure/GCP sinks without touching server code.

---

## 🗺️ Repository layout

```
/pkg
  /codec
  /core
    /transform
      cred_providers.go
      cred.go
      handlers.go
      load.go
      publish_tf.go
      relay.go
      router_build.go
      router_creds.go
      router_deps.go
      router_env.go
      router_guard.go
      router_helpers.go
      router_timeout.go
      router_wrap.go
      types_registry.go
  /electrician
  /manifest
  /middleware
    /auth
    /logger
    /metrics
  /transport/httpx
    router.go
  /utils
    get_request_id.go
    wrap_response_writer.go

.gitignore
.tool-versions
go.mod
go.sum
```

**What lives where**

* **`pkg/core`** — router construction, credentials, guards, timeouts, helpers; transform registry.
* **`pkg/electrician`** — typed pub, relay client, receiver→wire→sinks (S3/Kafka) with env‑driven config.
* **`pkg/transport/httpx`** — router abstraction (default: Chi).
* **`pkg/middleware`** — `auth`, `logger`, `metrics`.
* **`pkg/utils`** — request‑id extraction and response‑writer wrappers.

---

## 🚀 Quickstart


### 📁 `manifest.toml` (example)

```toml
# Routes
[[routes]]
method = "POST"
path   = "/echo"
[routes.handler]
type = "relay.publish"   # forwards request to relay target

# Receivers -> pipelines
[[receivers]]
address    = ":5001"
bufferSize = 1024

  [[receivers.pipeline]]
  dataType     = "com.example.Event"
  transformers = ["sanitize", "enrich"]
```

---

## ⚙️ Configuration

### HTTP server

* `SERVER_LISTEN_ADDRESS` — default `:4000`
* `SSL_SERVER_CERTIFICATE`, `SSL_SERVER_KEY` — when both present, TLS is enabled (TLS 1.3).

### Manifest path

* Set by `WithManifestEnv(...)`, e.g. `HERMES_MANIFEST` / `EXODUS_MANIFEST`. Falls back to `WithDefaultManifest(...)`.

### Electrician — forward/relay

```env
ELECTRICIAN_TARGET=host:port[,host2:port2]
ELECTRICIAN_TLS_ENABLE=true|false
ELECTRICIAN_COMPRESS=snappy
ELECTRICIAN_ENCRYPT=aesgcm
ELECTRICIAN_AES256_KEY_HEX=<64 hex chars>
ELECTRICIAN_STATIC_HEADERS=k=v,k2=v2

# OAuth2 CC (optional)
OAUTH_ISSUER_BASE=...
OAUTH_JWKS_URL=...
OAUTH_CLIENT_ID=...
OAUTH_CLIENT_SECRET=...
OAUTH_SCOPES=s1,s2
OAUTH_REFRESH_LEEWAY=20s
```

### Electrician — receiver

```env
ELECTRICIAN_RX_TLS_ENABLE=true|false
ELECTRICIAN_RX_TLS_SERVER_CRT=...
ELECTRICIAN_RX_TLS_SERVER_KEY=...
ELECTRICIAN_RX_TLS_CA=...
ELECTRICIAN_RX_TLS_SERVER_NAME=...

# OAuth2 validation (either/both)
OAUTH_JWKS_URL=...
OAUTH_INTROSPECT_URL=...
OAUTH_INTROSPECT_AUTH=basic|bearer
OAUTH_CLIENT_ID=...
OAUTH_CLIENT_SECRET=...
OAUTH_INTROSPECT_BEARER=...
```

### Sinks (optional)

**S3 (Parquet)**

```env
S3_BUCKET=...
S3_REGION=us-east-1
S3_ENDPOINT=http://localhost:4566
S3_SSE_MODE=aes256|aws:kms|s3
S3_KMS_KEY_ARN=...
PARQUET_COMPRESSION=zstd|snappy|gzip
ROLL_WINDOW_MS=300000
ROLL_MAX_RECORDS=250000
BATCH_MAX_RECORDS=500000
BATCH_MAX_BYTES_MB=256
BATCH_MAX_AGE_MS=300000
```

**Kafka**

```env
KAFKA_BROKERS=host:port[,...]
KAFKA_TOPIC=events
KAFKA_FORMAT=ndjson|json
KAFKA_KEY_TEMPLATE={customerId}
KAFKA_HEADERS=k=v,k2=v2
KAFKA_WRITER_BATCH_TIMEOUT_MS=400
KAFKA_TLS_ENABLE=true|false
KAFKA_TLS_CA_FILES=./tls/ca.crt,../tls/ca.crt
KAFKA_TLS_SERVER_NAME=localhost
KAFKA_TLS_CLIENT_CERT=...
KAFKA_TLS_CLIENT_KEY=...
KAFKA_SASL_MECHANISM=SCRAM-SHA-256|SCRAM-SHA-512
KAFKA_SASL_USERNAME=...
KAFKA_SASL_PASSWORD=...
```

---

## 🔌 Extensibility

* **New sinks**: implement `build<Provider>WriterFromEnv` in `pkg/electrician`, add to the sink aggregator. Deterministic start/stop order is enforced.
* **Alt router**: provide your own `httpx.Router` and override in your app’s Fx graph.
* **Auth/metrics**: swap or extend middleware modules without touching `serverfx`.

---

## 🧪 Testing

* Unit test handlers/transformers.
* Wiring tests with `fx.ValidateApp()` and a minimal manifest.
* Disable relay by leaving `ELECTRICIAN_TARGET` empty.

---

## ♻️ Conventions

* Small files, no cyclic deps, constructor functions per env‑driven feature.
* Errors are actionable; logs avoid secrets.
* Defaults favor safety; opt‑in to extras via env.
