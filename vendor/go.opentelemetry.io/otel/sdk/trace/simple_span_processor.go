// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trace // import "go.opentelemetry.io/otel/sdk/trace"

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
)

// simpleSpanProcessor is a SpanProcessor that synchronously sends all
// completed Spans to a trace.Exporter immediately.
type simpleSpanProcessor struct {
	exporterMu sync.RWMutex
	exporter   SpanExporter
	stopOnce   sync.Once
}

var _ SpanProcessor = (*simpleSpanProcessor)(nil)

// NewSimpleSpanProcessor returns a new SpanProcessor that will synchronously
// send completed spans to the exporter immediately.
//
// This SpanProcessor is not recommended for production use. The synchronous
// nature of this SpanProcessor make it good for testing, debugging, or
// showing examples of other feature, but it will be slow and have a high
// computation resource usage overhead. The BatchSpanProcessor is recommended
// for production use instead.
func NewSimpleSpanProcessor(exporter SpanExporter) SpanProcessor {
	ssp := &simpleSpanProcessor{
		exporter: exporter,
	}
	return ssp
}

// OnStart does nothing.
func (ssp *simpleSpanProcessor) OnStart(context.Context, ReadWriteSpan) {}

// OnEnd immediately exports a ReadOnlySpan.
func (ssp *simpleSpanProcessor) OnEnd(s ReadOnlySpan) {
	ssp.exporterMu.RLock()
	defer ssp.exporterMu.RUnlock()

	if ssp.exporter != nil && s.SpanContext().TraceFlags().IsSampled() {
		if err := ssp.exporter.ExportSpans(context.Background(), []ReadOnlySpan{s}); err != nil {
			otel.Handle(err)
		}
	}
}

// Shutdown shuts down the exporter this SimpleSpanProcessor exports to.
func (ssp *simpleSpanProcessor) Shutdown(ctx context.Context) error {
	var err error
	ssp.stopOnce.Do(func() {
		stopFunc := func(exp SpanExporter) (<-chan error, func()) {
			done := make(chan error)
			return done, func() { done <- exp.Shutdown(ctx) }
		}

		// The exporter field of the simpleSpanProcessor needs to be zeroed to
		// signal it is shut down, meaning all subsequent calls to OnEnd will
		// be gracefully ignored. This needs to be done synchronously to avoid
		// any race condition.
		//
		// A closure is used to keep reference to the exporter and then the
		// field is zeroed. This ensures the simpleSpanProcessor is shut down
		// before the exporter. This order is important as it avoids a
		// potential deadlock. If the exporter shut down operation generates a
		// span, that span would need to be exported. Meaning, OnEnd would be
		// called and try acquiring the lock that is held here.
		ssp.exporterMu.Lock()
		done, shutdown := stopFunc(ssp.exporter)
		ssp.exporter = nil
		ssp.exporterMu.Unlock()

		go shutdown()

		// Wait for the exporter to shut down or the deadline to expire.
		select {
		case err = <-done:
		case <-ctx.Done():
			// It is possible for the exporter to have immediately shut down
			// and the context to be done simultaneously. In that case this
			// outer select statement will randomly choose a case. This will
			// result in a different returned error for similar scenarios.
			// Instead, double check if the exporter shut down at the same
			// time and return that error if so. This will ensure consistency
			// as well as ensure the caller knows the exporter shut down
			// successfully (they can already determine if the deadline is
			// expired given they passed the context).
			select {
			case err = <-done:
			default:
				err = ctx.Err()
			}
		}
	})
	return err
}

// ForceFlush does nothing as there is no data to flush.
func (ssp *simpleSpanProcessor) ForceFlush(context.Context) error {
	return nil
}

// MarshalLog is the marshaling function used by the logging system to represent this Span Processor.
func (ssp *simpleSpanProcessor) MarshalLog() interface{} {
	return struct {
		Type     string
		Exporter SpanExporter
	}{
		Type:     "SimpleSpanProcessor",
		Exporter: ssp.exporter,
	}
}
