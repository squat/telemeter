package metricsclient

import (
	"context"
	"net/http"

	clientmodel "github.com/prometheus/client_model/go"
)

type mock struct{}

func NewMock() *mock {
	return &mock{}
}

func (m *mock) Retrieve(context.Context, *http.Request) ([]*clientmodel.MetricFamily, error) {
	return nil, nil
}
