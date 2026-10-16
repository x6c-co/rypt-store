package api

import (
	"context"

	"github.com/x6c-co/rypt-store/internal/api/gen"
)

func (h *Handlers) GetHealthz(context.Context, gen.GetHealthzRequestObject) (gen.GetHealthzResponseObject, error) {
	return gen.GetHealthz200JSONResponse{Status: gen.HealthStatusOk}, nil
}

// GetReadyz checks the database and the current key provider (core 9).
func (h *Handlers) GetReadyz(ctx context.Context, _ gen.GetReadyzRequestObject) (gen.GetReadyzResponseObject, error) {
	st := h.d.Keys.Status()
	res := gen.Health{Status: gen.HealthStatusOk, Database: ptr("ok"), Provider: ptr("ok")}
	if err := h.d.Store.Ping(ctx); err != nil {
		res.Status, res.Database = gen.HealthStatusUnavailable, ptr("unreachable")
	}
	if st.ProviderDown[st.Current] {
		res.Status, res.Provider = gen.HealthStatusUnavailable, ptr(st.Current+" unreachable")
	}
	if res.Status != gen.HealthStatusOk {
		return gen.GetReadyz503JSONResponse(res), nil
	}
	return gen.GetReadyz200JSONResponse(res), nil
}
