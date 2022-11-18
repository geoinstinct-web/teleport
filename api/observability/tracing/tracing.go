// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracing

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// PropagationContext contains tracing information to be passed across service boundaries
type PropagationContext map[string]string

// TraceParent is the name of the header or query parameter that contains
// tracing context across service boundaries.
const TraceParent = "traceparent"

// PropagationContextFromContext creates a PropagationContext from the given context.Context. If the context
// does not contain any tracing information, the PropagationContext will be empty.
func PropagationContextFromContext(ctx context.Context, opts ...Option) PropagationContext {
	carrier := propagation.MapCarrier{}
	NewConfig(opts).TextMapPropagator.Inject(ctx, &carrier)
	return PropagationContext(carrier)
}

// WithPropagationContext injects any tracing information from the given PropagationContext into the
// given context.Context.
func WithPropagationContext(ctx context.Context, pc PropagationContext, opts ...Option) context.Context {
	return NewConfig(opts).TextMapPropagator.Extract(ctx, propagation.MapCarrier(pc))
}

// DefaultProvider returns the global default TracerProvider.
func DefaultProvider() oteltrace.TracerProvider {
	return otel.GetTracerProvider()
}

// HTTPTransportFormatter is a span formatter that may be provided to
// otelhttp.WithSpanNameFormatter to include the url path in the span
// names generated by an otelhttp.Transport
func HTTPTransportFormatter(_ string, r *http.Request) string {
	return "HTTP " + r.Method + " " + r.URL.Path
}

// HTTPHandlerFormatter is a span formatter that may be provided to
// otelhttp.WithSpanNameFormatter to include the component and url path in the span
// names generated by otelhttp.NewHandler
func HTTPHandlerFormatter(operation string, r *http.Request) string {
	return operation + " " + r.Method + " " + r.URL.Path
}
