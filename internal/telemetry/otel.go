package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type OTELConfig struct {
	TracesEndpoint  string
	MetricsEndpoint string
	TracesEnabled   bool
	MetricsEnabled  bool
	ServiceName     string
	FlushInterval   time.Duration
	MaxBatchSize    int
}

type OTELExporter struct {
	client  *http.Client
	cfg     OTELConfig
	traceID string

	spansMu sync.Mutex
	spans   []otlpSpan

	metricsMu sync.Mutex
	counters  map[string]*atomic.Int64
	histos    map[string]*histogram

	done chan struct{}
	wg   sync.WaitGroup
}

func NewOTELExporter(cfg OTELConfig) *OTELExporter {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "warden"
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.MaxBatchSize == 0 {
		cfg.MaxBatchSize = 512
	}

	e := &OTELExporter{
		client:   &http.Client{Timeout: 5 * time.Second},
		cfg:      cfg,
		traceID:  generateTraceID(),
		counters: make(map[string]*atomic.Int64),
		histos:   make(map[string]*histogram),
		done:     make(chan struct{}),
	}

	e.wg.Add(1)
	go e.flushLoop()

	return e
}

func (e *OTELExporter) LogRequest(ctx context.Context, entry RequestLog) error {
	span := otlpSpan{
		TraceID:           e.traceID,
		SpanID:            generateSpanID(),
		Name:              "warden.proxy",
		Kind:              3, // SERVER
		StartTimeUnixNano: time.Now().Add(-time.Duration(entry.DurationMs) * time.Millisecond).UnixNano(),
		EndTimeUnixNano:   time.Now().UnixNano(),
		Attributes: []otlpKeyValue{
			{Key: "http.method", Value: otlpValue{StringValue: stringPtr(entry.Method)}},
			{Key: "http.host", Value: otlpValue{StringValue: stringPtr(entry.Host)}},
			{Key: "http.target", Value: otlpValue{StringValue: stringPtr(entry.Path)}},
			{Key: "warden.action", Value: otlpValue{StringValue: stringPtr(entry.Action)}},
			{Key: "warden.policy", Value: otlpValue{StringValue: stringPtr(entry.Policy)}},
			{Key: "net.peer.ip", Value: otlpValue{StringValue: stringPtr(entry.ClientIP)}},
		},
	}

	if entry.UpstreamStatus > 0 {
		span.Attributes = append(span.Attributes, otlpKeyValue{
			Key:   "http.status_code",
			Value: otlpValue{IntValue: int64Ptr(int64(entry.UpstreamStatus))},
		})
	}

	if entry.Action == "deny" {
		span.Status = &otlpStatus{Code: 2, Message: entry.Reason}
	}

	e.spansMu.Lock()
	e.spans = append(e.spans, span)
	needsFlush := len(e.spans) >= e.cfg.MaxBatchSize
	e.spansMu.Unlock()

	e.recordRequestMetrics(entry)

	if needsFlush {
		go e.flush(context.Background())
	}

	return nil
}

func (e *OTELExporter) StartSpan(ctx context.Context, name string, attrs ...SpanAttr) (context.Context, SpanHandle) {
	if !e.cfg.TracesEnabled {
		return ctx, NoopSpan{}
	}

	parentID := spanIDFromContext(ctx)
	span := &otelSpanHandle{
		exporter: e,
		span: otlpSpan{
			TraceID:           e.traceID,
			SpanID:            generateSpanID(),
			ParentSpanID:      parentID,
			Name:              name,
			Kind:              1, // INTERNAL
			StartTimeUnixNano: time.Now().UnixNano(),
		},
	}

	for _, a := range attrs {
		span.span.Attributes = append(span.span.Attributes, otlpKeyValue{
			Key:   a.Key,
			Value: otlpValue{StringValue: stringPtr(a.Value)},
		})
	}

	return contextWithSpanID(ctx, span.span.SpanID), span
}

func (e *OTELExporter) RecordMetric(_ context.Context, name string, value float64, attrs ...MetricAttr) {
	if !e.cfg.MetricsEnabled {
		return
	}

	key := metricKey(name, attrs)

	if value == 1 {
		e.metricsMu.Lock()
		c, ok := e.counters[key]
		if !ok {
			c = &atomic.Int64{}
			e.counters[key] = c
		}
		e.metricsMu.Unlock()
		c.Add(1)
		return
	}

	e.metricsMu.Lock()
	h, ok := e.histos[key]
	if !ok {
		h = newHistogram()
		e.histos[key] = h
	}
	e.metricsMu.Unlock()
	h.observe(value)
}

func (e *OTELExporter) Close(ctx context.Context) error {
	close(e.done)
	e.wg.Wait()
	return e.flush(ctx)
}

func (e *OTELExporter) addSpan(s otlpSpan) {
	e.spansMu.Lock()
	defer e.spansMu.Unlock()
	e.spans = append(e.spans, s)
}

func (e *OTELExporter) flushLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.flush(context.Background())
		case <-e.done:
			return
		}
	}
}

func (e *OTELExporter) flush(ctx context.Context) error {
	if e.cfg.TracesEnabled {
		if err := e.flushSpans(ctx); err != nil {
			return err
		}
	}
	if e.cfg.MetricsEnabled {
		if err := e.flushMetrics(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (e *OTELExporter) flushSpans(ctx context.Context) error {
	e.spansMu.Lock()
	if len(e.spans) == 0 {
		e.spansMu.Unlock()
		return nil
	}
	batch := e.spans
	e.spans = nil
	e.spansMu.Unlock()

	payload := otlpTraceExport{
		ResourceSpans: []otlpResourceSpans{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{
					{Key: "service.name", Value: otlpValue{StringValue: stringPtr(e.cfg.ServiceName)}},
				},
			},
			ScopeSpans: []otlpScopeSpans{{
				Scope: otlpScope{Name: "warden", Version: "1.0.0"},
				Spans: batch,
			}},
		}},
	}

	return e.post(ctx, e.cfg.TracesEndpoint+"/v1/traces", payload)
}

func (e *OTELExporter) flushMetrics(ctx context.Context) error {
	e.metricsMu.Lock()
	if len(e.counters) == 0 && len(e.histos) == 0 {
		e.metricsMu.Unlock()
		return nil
	}

	var metrics []otlpMetric

	now := time.Now().UnixNano()
	for name, c := range e.counters {
		metrics = append(metrics, otlpMetric{
			Name: name,
			Sum: &otlpSum{
				DataPoints: []otlpNumberDataPoint{{
					AsInt:        int64Ptr(c.Load()),
					TimeUnixNano: now,
				}},
				AggregationTemporality: 2, // CUMULATIVE
				IsMonotonic:            true,
			},
		})
	}

	for name, h := range e.histos {
		dp := h.dataPoint(now)
		metrics = append(metrics, otlpMetric{
			Name: name,
			Histogram: &otlpHistogram{
				DataPoints:             []otlpHistogramDataPoint{dp},
				AggregationTemporality: 2,
			},
		})
	}
	e.metricsMu.Unlock()

	payload := otlpMetricExport{
		ResourceMetrics: []otlpResourceMetrics{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{
					{Key: "service.name", Value: otlpValue{StringValue: stringPtr(e.cfg.ServiceName)}},
				},
			},
			ScopeMetrics: []otlpScopeMetrics{{
				Scope:   otlpScope{Name: "warden", Version: "1.0.0"},
				Metrics: metrics,
			}},
		}},
	}

	return e.post(ctx, e.cfg.MetricsEndpoint+"/v1/metrics", payload)
}

func (e *OTELExporter) post(ctx context.Context, url string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal OTLP: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("OTLP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("OTLP export: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("OTLP export: %s", resp.Status)
	}
	return nil
}

func (e *OTELExporter) recordRequestMetrics(entry RequestLog) {
	if !e.cfg.MetricsEnabled {
		return
	}

	ctx := context.Background()
	attrs := []MetricAttr{
		{Key: "http.method", Value: entry.Method},
		{Key: "warden.action", Value: entry.Action},
	}
	e.RecordMetric(ctx, "warden.requests.total", 1, attrs...)
	e.RecordMetric(ctx, "warden.request.duration_ms", float64(entry.DurationMs), attrs...)

	if entry.Action == "deny" {
		e.RecordMetric(ctx, "warden.requests.denied", 1,
			MetricAttr{Key: "reason", Value: entry.Reason})
	}
}

type otelSpanHandle struct {
	exporter *OTELExporter
	span     otlpSpan
}

func (h *otelSpanHandle) End() {
	h.span.EndTimeUnixNano = time.Now().UnixNano()
	h.exporter.addSpan(h.span)
}

func (h *otelSpanHandle) SetStatus(code int, msg string) {
	h.span.Status = &otlpStatus{Code: code, Message: msg}
}

func (h *otelSpanHandle) AddAttr(key string, value any) {
	h.span.Attributes = append(h.span.Attributes, otlpKeyValue{
		Key:   key,
		Value: otlpValue{StringValue: stringPtr(fmt.Sprintf("%v", value))},
	})
}

// Context key for span propagation
type spanIDKey struct{}

func contextWithSpanID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, spanIDKey{}, id)
}

func spanIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(spanIDKey{}).(string); ok {
		return v
	}
	return ""
}

func generateTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func metricKey(name string, attrs []MetricAttr) string {
	key := name
	for _, a := range attrs {
		key += "|" + a.Key + "=" + a.Value
	}
	return key
}

func stringPtr(s string) *string { return &s }
func int64Ptr(i int64) *int64    { return &i }
