package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/store"
)

func pageLimit(l *int) int {
	if l == nil || *l < 1 {
		return 50
	}
	return min(*l, 500)
}

func headJSON(h *store.AuditHead) gen.AuditHead {
	return gen.AuditHead{ChainId: h.ChainID, Seq: h.HeadSeq, Hash: h.HeadHash, AnchorSeq: h.AnchorSeq, AnchorHash: h.AnchorHash}
}

// actorNames resolves actor IDs to display names for one response.
type actorNames struct {
	h     *Handlers
	cache map[string]string
}

func (a *actorNames) name(ctx context.Context, kind, id string) string {
	if id == "" {
		return ""
	}
	key := kind + ":" + id
	if n, ok := a.cache[key]; ok {
		return n
	}
	n := ""
	switch kind {
	case audit.ActorUser:
		if u, err := a.h.d.Store.GetUser(ctx, id); err == nil {
			n = u.DisplayName
		}
	case audit.ActorServiceToken:
		if t, err := a.h.d.Store.GetServiceToken(ctx, id); err == nil {
			n = t.Name
		}
	}
	a.cache[key] = n
	return n
}

func (h *Handlers) names() *actorNames { return &actorNames{h: h, cache: map[string]string{}} }

func eventJSON(ctx context.Context, e store.AuditEvent, names *actorNames) gen.AuditEvent {
	x := audit.ToExported(e)
	var meta map[string]any
	_ = json.Unmarshal(x.Metadata, &meta)
	if meta == nil {
		meta = map[string]any{}
	}
	return gen.AuditEvent{
		Id: x.ID, ChainId: x.ChainID, Seq: x.Seq, Ts: x.TS, ActorKind: gen.AuditEventActorKind(x.ActorKind), ActorId: x.ActorID,
		ActorDisplay: strPtr(names.name(ctx, e.ActorKind, e.ActorID)), Action: x.Action, TargetKind: x.TargetKind,
		TargetId: x.TargetID, ProjectId: x.ProjectID, EnvironmentId: x.EnvironmentID, Result: gen.AuditEventResult(x.Result),
		Ip: x.IP, UserAgent: x.UserAgent, RequestId: x.RequestID, ProviderRequestId: x.ProviderRequestID, Metadata: meta,
		PrevHash: x.PrevHash, Hash: x.Hash,
	}
}

func (h *Handlers) auditPage(ctx context.Context, chainID string, f store.AuditFilter, limit *int, cursor *string) (gen.AuditPage, error) {
	head, err := h.d.Store.GetAuditHead(ctx, chainID)
	if err != nil {
		return gen.AuditPage{}, err
	}
	evs, next, err := h.d.Store.ListAuditEvents(ctx, chainID, f, store.Page{Limit: pageLimit(limit), Cursor: deref(cursor)})
	if errors.Is(err, store.ErrConflict) {
		return gen.AuditPage{}, errInvalid("cursor", "the cursor is invalid")
	}
	if err != nil {
		return gen.AuditPage{}, err
	}
	names := h.names()
	out := make([]gen.AuditEvent, 0, len(evs))
	for _, e := range evs {
		out = append(out, eventJSON(ctx, e, names))
	}
	return gen.AuditPage{Events: out, NextCursor: strPtr(next), Head: headJSON(head)}, nil
}

func (h *Handlers) ListTenantAudit(ctx context.Context, req gen.ListTenantAuditRequestObject) (gen.ListTenantAuditResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.AuditRead); err != nil {
		return nil, err
	}
	f := store.AuditFilter{ActorID: deref(req.Params.Actor), Action: deref(req.Params.Action), From: req.Params.From, To: req.Params.To}
	if slug := deref(req.Params.Project); slug != "" {
		p, err := h.d.Store.GetProjectBySlug(ctx, s.tenant.ID, slug)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errNotFound("project")
		}
		if err != nil {
			return nil, err
		}
		f.ProjectID = p.ID
	}
	page, err := h.auditPage(ctx, s.tenant.ID, f, req.Params.Limit, req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	return gen.ListTenantAudit200JSONResponse(page), nil
}

// exportStream streams a chain as JSON Lines through a pipe.
func (h *Handlers) exportStream(ctx context.Context, chainID string, from, to *time.Time) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		err := audit.Export(context.WithoutCancel(ctx), h.d.Store, chainID, from, to, func(b []byte) error {
			_, err := pw.Write(b)
			return err
		})
		pw.CloseWithError(err)
	}()
	return pr
}

func (h *Handlers) ExportTenantAudit(ctx context.Context, req gen.ExportTenantAuditRequestObject) (gen.ExportTenantAuditResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.AuditRead); err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "audit.export",
		TargetKind: "audit_chain", TargetID: s.tenant.ID}, nil)
	if err != nil {
		return nil, err
	}
	header(ctx).Set("Content-Disposition", `attachment; filename="audit-`+s.tenant.Slug+`.jsonl"`)
	return gen.ExportTenantAudit200ApplicationjsonlResponse{Body: h.exportStream(ctx, s.tenant.ID, req.Params.From, req.Params.To)}, nil
}

func (h *Handlers) verifyChain(ctx context.Context, chainID string) (gen.AuditVerify, error) {
	res, err := audit.Verify(ctx, h.d.Store, chainID)
	if err != nil {
		return gen.AuditVerify{}, err
	}
	head, err := h.d.Store.GetAuditHead(ctx, chainID)
	if err != nil {
		return gen.AuditVerify{}, err
	}
	return gen.AuditVerify{Ok: res.OK, Seq: res.Seq, Hash: res.Hash, Reason: strPtr(res.Reason), Checked: res.Checked, Head: headJSON(head)}, nil
}

func (h *Handlers) VerifyTenantAudit(ctx context.Context, req gen.VerifyTenantAuditRequestObject) (gen.VerifyTenantAuditResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.AuditRead); err != nil {
		return nil, err
	}
	v, err := h.verifyChain(ctx, s.tenant.ID)
	if err != nil {
		return nil, err
	}
	return gen.VerifyTenantAudit200JSONResponse(v), nil
}

// instanceAdmin returns the caller when they are an instance admin.
func instanceAdmin(ctx context.Context) (*authz.Principal, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if !authz.Can(p, authz.InstanceManage, authz.Resource{}) {
		return nil, errForbidden("this needs an instance admin")
	}
	return p, nil
}

func (h *Handlers) ListInstanceAudit(ctx context.Context, req gen.ListInstanceAuditRequestObject) (gen.ListInstanceAuditResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	f := store.AuditFilter{ActorID: deref(req.Params.Actor), Action: deref(req.Params.Action), From: req.Params.From, To: req.Params.To}
	page, err := h.auditPage(ctx, store.InstanceChain, f, req.Params.Limit, req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	return gen.ListInstanceAudit200JSONResponse(page), nil
}

func (h *Handlers) ExportInstanceAudit(ctx context.Context, req gen.ExportInstanceAuditRequestObject) (gen.ExportInstanceAuditResponseObject, error) {
	p, err := instanceAdmin(ctx)
	if err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID, Action: "audit.export",
		TargetKind: "audit_chain", TargetID: store.InstanceChain}, nil)
	if err != nil {
		return nil, err
	}
	header(ctx).Set("Content-Disposition", `attachment; filename="audit-instance.jsonl"`)
	return gen.ExportInstanceAudit200ApplicationjsonlResponse{Body: h.exportStream(ctx, store.InstanceChain, req.Params.From, req.Params.To)}, nil
}

func (h *Handlers) VerifyInstanceAudit(ctx context.Context, _ gen.VerifyInstanceAuditRequestObject) (gen.VerifyInstanceAuditResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	v, err := h.verifyChain(ctx, store.InstanceChain)
	if err != nil {
		return nil, err
	}
	return gen.VerifyInstanceAudit200JSONResponse(v), nil
}
