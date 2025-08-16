package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	chimd "github.com/go-chi/chi/v5/middleware"
	"github.com/joeydtaylor/steeze-core/pkg/core/transform"
	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
)

func wrapRoute(rt manifest.Route, d BuildDeps) http.HandlerFunc {
	switch rt.Handler.Type {
	case manifest.HandlerInproc:
		h, ok := Lookup(rt.Handler.Name)
		if !ok {
			return func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "handler not found", http.StatusInternalServerError)
			}
		}
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			out, status, err := h(r.Context(), body)
			if err != nil {
				http.Error(w, err.Error(), statusIf(status, http.StatusInternalServerError))
				return
			}
			writeJSON(w, out, statusIf(status, http.StatusOK))
		}

	case manifest.HandlerRelayReq:
		return func(w http.ResponseWriter, r *http.Request) {
			if d.Relay == nil {
				http.Error(w, "relay unavailable", http.StatusBadGateway)
				return
			}
			body, _ := io.ReadAll(r.Body)
			ctx := r.Context()
			if dl := rt.Handler.Relay.DeadlineMS; dl > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(dl)*time.Millisecond)
				defer cancel()
			}
			hdrs := map[string]string{}
			if rid := chimd.GetReqID(ctx); rid != "" {
				hdrs["X-Request-Id"] = rid
			}
			if creds, err := issueCreds(d, r, rt); err == nil && creds.HeaderName != "" && creds.HeaderValue != "" {
				hdrs[creds.HeaderName] = creds.HeaderValue
				for k, v := range creds.Extra {
					hdrs[k] = v
				}
			}
			reply, err := d.Relay.Request(ctx, RelayRequest{
				Topic:   rt.Handler.Relay.Topic,
				Body:    body,
				Headers: hdrs,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, reply, http.StatusOK)
		}

	case manifest.HandlerRelayPublish:
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			canon := body

			// 1) Canonicalize if a datatype is declared
			typeName := strings.TrimSpace(rt.Handler.Relay.DataType)
			if typeName != "" {
				_, out, err := ValidateAndCanonicalize(typeName, body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				canon = out
			}

			// 2) Publish-side transforms (manifest-driven)
			if rs := rt.Handler.Relay; rs != nil && len(rs.Transformers) > 0 && typeName != "" {
				fmt.Printf("DEBUG publish: applying %v for type %q\n", rs.Transformers, typeName)

				adapters, elemType, err := transform.ResolveWithType(typeName, rs.Transformers)
				if err != nil {
					http.Error(w, "transform resolve: "+err.Error(), http.StatusBadRequest)
					return
				}

				dstPtr := reflect.New(elemType).Interface()
				if err := json.Unmarshal(canon, dstPtr); err != nil {
					http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
					return
				}
				val := reflect.ValueOf(dstPtr).Elem().Interface()
				fmt.Printf("DEBUG publish: before transforms: %#v\n", val)

				for _, fn := range adapters {
					val, err = fn(val)
					if err != nil {
						http.Error(w, "transform: "+err.Error(), http.StatusBadRequest)
						return
					}
					fmt.Printf("DEBUG publish: after step: %#v\n", val)
				}

				out, err := json.Marshal(val)
				if err != nil {
					http.Error(w, "encode: "+err.Error(), http.StatusBadRequest)
					return
				}
				canon = out

				// safety: re-canonicalize
				if _, out2, err := ValidateAndCanonicalize(typeName, canon); err == nil {
					canon = out2
				}
			} else if typeName != "" {
				fmt.Printf("DEBUG publish: no transforms for type %q (list empty or missing)\n", typeName)
			}

			// 3A) Typed path
			if d.Typed != nil && typeName != "" {
				if _, elemType, err := transform.ResolveWithType(typeName, rt.Handler.Relay.Transformers); err == nil && elemType != nil {
					dstPtr := reflect.New(elemType).Interface()
					if err := json.Unmarshal(canon, dstPtr); err != nil {
						http.Error(w, "decode typed: "+err.Error(), http.StatusBadRequest)
						return
					}
					val := reflect.ValueOf(dstPtr).Elem().Interface()

					hdrs := map[string]string{"X-Relay-Type": typeName}
					if rid := chimd.GetReqID(r.Context()); rid != "" {
						hdrs["X-Request-Id"] = rid
					}
					if creds, err := issueCreds(d, r, rt); err == nil && creds.HeaderName != "" {
						hdrs[creds.HeaderName] = creds.HeaderValue
						for k, v := range creds.Extra {
							hdrs[k] = v
						}
					}
					if err := d.Typed.Publish(r.Context(), rt.Handler.Relay.Topic, typeName, val, hdrs); err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					w.WriteHeader(http.StatusAccepted)
					return
				}
			}

			// 3B) Byte-level path
			if d.Relay == nil {
				http.Error(w, "relay unavailable", http.StatusBadGateway)
				return
			}
			hdrs := map[string]string{"Content-Type": "application/json"}
			if typeName != "" {
				hdrs["X-Relay-Type"] = typeName
			}
			if rid := chimd.GetReqID(r.Context()); rid != "" {
				hdrs["X-Request-Id"] = rid
			}
			if creds, err := issueCreds(d, r, rt); err == nil && creds.HeaderName != "" {
				hdrs[creds.HeaderName] = creds.HeaderValue
				for k, v := range creds.Extra {
					hdrs[k] = v
				}
			}
			if err := d.Relay.Publish(r.Context(), RelayRequest{
				Topic:   rt.Handler.Relay.Topic,
				Body:    canon,
				Headers: hdrs,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}

	case manifest.HandlerProxy:
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "proxy handler not implemented", http.StatusNotImplemented)
		}

	default:
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unknown handler type", http.StatusInternalServerError)
		}
	}
}
