package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOTELExporterLogRequest(t *testing.T) {
	var received atomic.Int32
	var lastBody []byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastBody, _ = io.ReadAll(r.Body)
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTELExporter(OTELConfig{
		TracesEndpoint:  srv.URL,
		MetricsEndpoint: srv.URL,
		TracesEnabled:   true,
		MetricsEnabled:  true,
		FlushInterval:   100 * time.Millisecond,
	})

	err := exp.LogRequest(context.Background(), RequestLog{
		ClientIP:       "10.0.0.1",
		Host:           "api.github.com",
		Method:         "GET",
		Path:           "/repos/org/app",
		Policy:         "github-read",
		Action:         "allow",
		UpstreamStatus: 200,
		DurationMs:     42,
	})
	if err != nil {
		t.Fatal(err)
	}

	exp.Close(context.Background())

	if received.Load() == 0 {
		t.Fatal("expected at least one export call")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(lastBody) == 0 {
		t.Fatal("empty export body")
	}

	var payload map[string]any
	if err := json.Unmarshal(lastBody, &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestOTELExporterStartSpan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTELExporter(OTELConfig{
		TracesEndpoint: srv.URL,
		TracesEnabled:  true,
		FlushInterval:  1 * time.Hour,
	})

	ctx := context.Background()
	ctx, span := exp.StartSpan(ctx, "test.operation",
		SpanAttr{Key: "key1", Value: "val1"},
	)
	span.AddAttr("key2", "val2")
	span.SetStatus(0, "OK")
	span.End()

	// Verify span was added
	exp.spansMu.Lock()
	count := len(exp.spans)
	exp.spansMu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 span, got %d", count)
	}

	// Verify context propagation
	childCtx, child := exp.StartSpan(ctx, "child.op")
	child.End()
	_ = childCtx

	exp.spansMu.Lock()
	if len(exp.spans) != 2 {
		t.Errorf("expected 2 spans, got %d", len(exp.spans))
	}
	if exp.spans[1].ParentSpanID == "" {
		t.Error("child span should have parent ID")
	}
	exp.spansMu.Unlock()

	exp.Close(context.Background())
}

func TestOTELExporterDisabledSpan(t *testing.T) {
	exp := NewOTELExporter(OTELConfig{
		TracesEnabled: false,
		FlushInterval: 1 * time.Hour,
	})

	ctx, span := exp.StartSpan(context.Background(), "noop")
	span.End()
	_ = ctx

	exp.spansMu.Lock()
	if len(exp.spans) != 0 {
		t.Error("disabled traces should produce no spans")
	}
	exp.spansMu.Unlock()

	exp.Close(context.Background())
}

func TestOTELExporterRecordMetric(t *testing.T) {
	exp := NewOTELExporter(OTELConfig{
		MetricsEnabled: true,
		FlushInterval:  1 * time.Hour,
	})

	ctx := context.Background()

	// Counter
	exp.RecordMetric(ctx, "requests.total", 1, MetricAttr{Key: "method", Value: "GET"})
	exp.RecordMetric(ctx, "requests.total", 1, MetricAttr{Key: "method", Value: "GET"})

	key := "requests.total|method=GET"
	exp.metricsMu.Lock()
	c, ok := exp.counters[key]
	exp.metricsMu.Unlock()
	if !ok {
		t.Fatal("counter not found")
	}
	if c.Load() != 2 {
		t.Errorf("counter = %d, want 2", c.Load())
	}

	// Histogram
	exp.RecordMetric(ctx, "duration_ms", 42, MetricAttr{Key: "method", Value: "GET"})
	exp.RecordMetric(ctx, "duration_ms", 150, MetricAttr{Key: "method", Value: "GET"})

	histKey := "duration_ms|method=GET"
	exp.metricsMu.Lock()
	h, ok := exp.histos[histKey]
	exp.metricsMu.Unlock()
	if !ok {
		t.Fatal("histogram not found")
	}
	h.mu.Lock()
	if h.count != 2 {
		t.Errorf("histogram count = %d, want 2", h.count)
	}
	if h.sum != 192 {
		t.Errorf("histogram sum = %f, want 192", h.sum)
	}
	h.mu.Unlock()

	exp.Close(context.Background())
}

func TestOTELExporterMetricsFlush(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTELExporter(OTELConfig{
		MetricsEndpoint: srv.URL,
		MetricsEnabled:  true,
		FlushInterval:   1 * time.Hour,
	})

	exp.RecordMetric(context.Background(), "test", 1)

	exp.Close(context.Background())

	if received.Load() == 0 {
		t.Error("expected metrics flush on close")
	}
}

func TestOTELExporterConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTELExporter(OTELConfig{
		TracesEndpoint:  srv.URL,
		MetricsEndpoint: srv.URL,
		TracesEnabled:   true,
		MetricsEnabled:  true,
		FlushInterval:   1 * time.Hour,
	})

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exp.LogRequest(ctx, RequestLog{
				Host:   "example.com",
				Method: "GET",
				Path:   "/",
				Action: "allow",
			})
		}()
	}
	wg.Wait()

	exp.Close(context.Background())
}

func TestHistogramBuckets(t *testing.T) {
	h := newHistogram()

	h.observe(0.5)  // bucket 0 (<=1)
	h.observe(3)    // bucket 1 (<=5)
	h.observe(50)   // bucket 4 (<=50)
	h.observe(9999) // overflow bucket

	dp := h.dataPoint(0)

	if dp.Count != 4 {
		t.Errorf("count = %d, want 4", dp.Count)
	}
	if *dp.Sum != 10052.5 {
		t.Errorf("sum = %f, want 10052.5", *dp.Sum)
	}
	if dp.BucketCounts[0] != 1 {
		t.Errorf("bucket[0] = %d, want 1", dp.BucketCounts[0])
	}
	if dp.BucketCounts[1] != 1 {
		t.Errorf("bucket[1] = %d, want 1", dp.BucketCounts[1])
	}
	if dp.BucketCounts[4] != 1 {
		t.Errorf("bucket[4] = %d, want 1", dp.BucketCounts[4])
	}
	if dp.BucketCounts[len(defaultBounds)] != 1 {
		t.Errorf("overflow bucket = %d, want 1", dp.BucketCounts[len(defaultBounds)])
	}
}
