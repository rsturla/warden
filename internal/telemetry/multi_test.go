package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestMultiExporterLogRequest(t *testing.T) {
	var buf bytes.Buffer
	slogExp := NewSlogExporter(slog.New(slog.NewJSONHandler(&buf, nil)))

	calls := 0
	countExp := &countingExporter{logFn: func() { calls++ }}

	multi := NewMultiExporter(slogExp, countExp)

	err := multi.LogRequest(context.Background(), RequestLog{
		Host:   "example.com",
		Method: "GET",
		Path:   "/",
		Action: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}

	if buf.Len() == 0 {
		t.Error("slog exporter should have written")
	}
	if calls != 1 {
		t.Errorf("counting exporter called %d times", calls)
	}
}

func TestMultiExporterClose(t *testing.T) {
	closed := 0
	exp := &countingExporter{closeFn: func() { closed++ }}
	multi := NewMultiExporter(exp, exp)

	if err := multi.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if closed != 2 {
		t.Errorf("close called %d times, want 2", closed)
	}
}

func TestMultiExporterSpanPropagation(t *testing.T) {
	var spans int
	exp := &countingExporter{startSpanFn: func() { spans++ }}
	multi := NewMultiExporter(exp, exp)

	ctx, span := multi.StartSpan(context.Background(), "test")
	_ = ctx
	span.End()

	if spans != 2 {
		t.Errorf("startSpan called %d times, want 2", spans)
	}
}

type countingExporter struct {
	logFn       func()
	closeFn     func()
	startSpanFn func()
}

func (e *countingExporter) LogRequest(_ context.Context, _ RequestLog) error {
	if e.logFn != nil {
		e.logFn()
	}
	return nil
}

func (e *countingExporter) StartSpan(ctx context.Context, _ string, _ ...SpanAttr) (context.Context, SpanHandle) {
	if e.startSpanFn != nil {
		e.startSpanFn()
	}
	return ctx, NoopSpan{}
}

func (e *countingExporter) RecordMetric(_ context.Context, _ string, _ float64, _ ...MetricAttr) {}

func (e *countingExporter) Close(_ context.Context) error {
	if e.closeFn != nil {
		e.closeFn()
	}
	return nil
}
