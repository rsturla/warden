package telemetry

import "context"

type MultiExporter struct {
	exporters []TelemetryExporter
}

func NewMultiExporter(exporters ...TelemetryExporter) *MultiExporter {
	return &MultiExporter{exporters: exporters}
}

func (m *MultiExporter) LogRequest(ctx context.Context, entry RequestLog) error {
	for _, e := range m.exporters {
		if err := e.LogRequest(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiExporter) StartSpan(ctx context.Context, name string, attrs ...SpanAttr) (context.Context, SpanHandle) {
	var handles []SpanHandle
	for _, e := range m.exporters {
		var h SpanHandle
		ctx, h = e.StartSpan(ctx, name, attrs...)
		handles = append(handles, h)
	}
	return ctx, &multiSpanHandle{handles: handles}
}

func (m *MultiExporter) RecordMetric(ctx context.Context, name string, value float64, attrs ...MetricAttr) {
	for _, e := range m.exporters {
		e.RecordMetric(ctx, name, value, attrs...)
	}
}

func (m *MultiExporter) Close(ctx context.Context) error {
	for _, e := range m.exporters {
		if err := e.Close(ctx); err != nil {
			return err
		}
	}
	return nil
}

type multiSpanHandle struct {
	handles []SpanHandle
}

func (h *multiSpanHandle) End() {
	for _, s := range h.handles {
		s.End()
	}
}

func (h *multiSpanHandle) SetStatus(code int, msg string) {
	for _, s := range h.handles {
		s.SetStatus(code, msg)
	}
}

func (h *multiSpanHandle) AddAttr(key string, value any) {
	for _, s := range h.handles {
		s.AddAttr(key, value)
	}
}
