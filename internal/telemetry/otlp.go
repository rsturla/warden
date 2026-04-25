package telemetry

import "sync"

// OTLP/HTTP JSON wire format types
// https://opentelemetry.io/docs/specs/otlp/

// --- Traces ---

type otlpTraceExport struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano int64          `json:"startTimeUnixNano,string"`
	EndTimeUnixNano   int64          `json:"endTimeUnixNano,string"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            *otlpStatus    `json:"status,omitempty"`
}

type otlpStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// --- Metrics ---

type otlpMetricExport struct {
	ResourceMetrics []otlpResourceMetrics `json:"resourceMetrics"`
}

type otlpResourceMetrics struct {
	Resource     otlpResource       `json:"resource"`
	ScopeMetrics []otlpScopeMetrics `json:"scopeMetrics"`
}

type otlpScopeMetrics struct {
	Scope   otlpScope    `json:"scope"`
	Metrics []otlpMetric `json:"metrics"`
}

type otlpMetric struct {
	Name      string         `json:"name"`
	Sum       *otlpSum       `json:"sum,omitempty"`
	Histogram *otlpHistogram `json:"histogram,omitempty"`
}

type otlpSum struct {
	DataPoints             []otlpNumberDataPoint `json:"dataPoints"`
	AggregationTemporality int                   `json:"aggregationTemporality"`
	IsMonotonic            bool                  `json:"isMonotonic"`
}

type otlpNumberDataPoint struct {
	AsInt        *int64 `json:"asInt,omitempty,string"`
	TimeUnixNano int64  `json:"timeUnixNano,string"`
}

type otlpHistogram struct {
	DataPoints             []otlpHistogramDataPoint `json:"dataPoints"`
	AggregationTemporality int                      `json:"aggregationTemporality"`
}

type otlpHistogramDataPoint struct {
	Count          int64     `json:"count,string"`
	Sum            *float64  `json:"sum,omitempty"`
	BucketCounts   []int64   `json:"bucketCounts"`
	ExplicitBounds []float64 `json:"explicitBounds"`
	TimeUnixNano   int64     `json:"timeUnixNano,string"`
}

// --- Shared ---

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpKeyValue struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *int64  `json:"intValue,omitempty,string"`
}

// --- Histogram implementation ---

var defaultBounds = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000}

type histogram struct {
	mu     sync.Mutex
	bounds []float64
	counts []int64
	sum    float64
	count  int64
}

func newHistogram() *histogram {
	return &histogram{
		bounds: defaultBounds,
		counts: make([]int64, len(defaultBounds)+1),
	}
}

func (h *histogram) observe(val float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sum += val
	h.count++

	for i, b := range h.bounds {
		if val <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.bounds)]++
}

func (h *histogram) dataPoint(timeNano int64) otlpHistogramDataPoint {
	h.mu.Lock()
	defer h.mu.Unlock()

	counts := make([]int64, len(h.counts))
	copy(counts, h.counts)
	sum := h.sum

	return otlpHistogramDataPoint{
		Count:          h.count,
		Sum:            &sum,
		BucketCounts:   counts,
		ExplicitBounds: h.bounds,
		TimeUnixNano:   timeNano,
	}
}
