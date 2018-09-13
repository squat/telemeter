package metricsclient

import (
	"context"
	"math/rand"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	clientmodel "github.com/prometheus/client_model/go"
)

type mock struct {
	gauge    prometheus.Gauge
	registry *prometheus.Registry
}

func NewMock() *mock {
	r := prometheus.NewRegistry()
	g := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "mock metric",
			Help: "This is a mock metric.",
		},
	)
	r.MustRegister(g)

	return &mock{gauge: g, registry: r}
}

func (m *mock) Retrieve(context.Context, *http.Request) ([]*clientmodel.MetricFamily, error) {
	m.gauge.Set(rand.Float64())
	return m.registry.Gather()
}
