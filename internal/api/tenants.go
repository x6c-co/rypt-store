package api

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

// InvitationTTL is how long an invitation link works.
const InvitationTTL = 7 * 24 * time.Hour

func (h *Handlers) ListTenants(ctx context.Context, req gen.ListTenantsRequestObject) (gen.ListTenantsResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	out := []gen.Tenant{}
	if req.Params.Scope != nil && *req.Params.Scope == gen.ListTenantsParamsScopeAll {
		if !authz.Can(p, authz.InstanceManage, authz.Resource{}) {
			return nil, errForbidden("listing every tenant needs an instance admin")
		}
		ts, err := h.d.Store.ListAllTenants(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			out = append(out, tenantJSON(t, ""))
		}
		return gen.ListTenants200JSONResponse{Tenants: out}, nil
	}
	ts, err := h.d.Store.ListTenantsForUser(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		out = append(out, tenantJSON(t.Tenant, t.Role))
	}
	return gen.ListTenants200JSONResponse{Tenants: out}, nil
}

func (h *Handlers) CreateTenant(ctx context.Context, req gen.CreateTenantRequestObject) (gen.CreateTenantResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if !authz.Can(p, authz.InstanceManage, authz.Resource{}) {
		return nil, errForbidden("creating tenants needs an instance admin")
	}
	if req.Body == nil {
		return nil, errInvalid("name", "name is required")
	}
	name := strings.TrimSpace(req.Body.Name)
	if name == "" || len(name) > 128 {
		return nil, errInvalid("name", "enter a name of at most 128 characters")
	}
	slug := Slugify(name)
	if req.Body.Slug != nil {
		if slug = *req.Body.Slug; !validSlug(slug) {
			return nil, errInvalid("slug", "use lowercase letters, digits and dashes")
		}
	}
	now := h.now()
	t := store.Tenant{ID: ids.New(), Name: name, Slug: slug, CreatedAt: now}
	owner := &store.Membership{TenantID: t.ID, UserID: p.ID, Role: string(authz.Owner), CreatedAt: now}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "tenant.create", TargetKind: "tenant", TargetID: t.ID, Metadata: map[string]any{"name": name, "slug": slug}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateTenant(ctx, t, owner, ev) })
	if err != nil {
		return nil, err
	}
	return gen.CreateTenant201JSONResponse(tenantJSON(t, string(authz.Owner))), nil
}

func (h *Handlers) GetTenant(ctx context.Context, req gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	return gen.GetTenant200JSONResponse(tenantJSON(*s.tenant, string(s.p.Role))), nil
}

func memberJSON(m store.Member) gen.Member {
	return gen.Member{UserId: m.UserID, Email: m.Email, DisplayName: m.DisplayName, Role: gen.Role(m.Role), CreatedAt: m.CreatedAt}
}

func (h *Handlers) ListMembers(ctx context.Context, req gen.ListMembersRequestObject) (gen.ListMembersResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectRead); err != nil {
		return nil, err
	}
	ms, err := h.d.Store.ListMembers(ctx, s.tenant.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Member, 0, len(ms))
	for _, m := range ms {
		out = append(out, memberJSON(m))
	}
	return gen.ListMembers200JSONResponse{Members: out}, nil
}

// targetMember loads a member of the scoped tenant; a non-member is 404.
func (h *Handlers) targetMember(ctx context.Context, s scope, userID string) (*store.Membership, error) {
	m, err := h.d.Store.GetMembership(ctx, s.tenant.ID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("member")
	}
	return m, err
}

func (h *Handlers) UpdateMember(ctx context.Context, req gen.UpdateMemberRequestObject) (gen.UpdateMemberResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.MemberManage); err != nil {
		return nil, err
	}
	if req.Body == nil || !authz.ValidRole(string(req.Body.Role)) {
		return nil, errInvalid("role", "role must be owner, admin, member, or viewer")
	}
	m, err := h.targetMember(ctx, s, req.User)
	if err != nil {
		return nil, err
	}
	to := authz.Role(req.Body.Role)
	if !authz.CanAssignRole(s.p.Role, authz.Role(m.Role), to) {
		return nil, errForbidden("you can change only roles below your own")
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID,
		Action: "member.role.update", TargetKind: "user", TargetID: m.UserID, Metadata: map[string]any{"from": m.Role, "to": string(to)}},
		func(ev *store.AuditEvent) error {
			return h.d.Store.UpdateMemberRole(ctx, s.tenant.ID, m.UserID, string(to), ev)
		})
	if err != nil {
		return nil, err
	}
	ms, err := h.d.Store.ListMembers(ctx, s.tenant.ID)
	if err != nil {
		return nil, err
	}
	for _, x := range ms {
		if x.UserID == m.UserID {
			return gen.UpdateMember200JSONResponse(memberJSON(x)), nil
		}
	}
	return nil, errNotFound("member")
}

func (h *Handlers) RemoveMember(ctx context.Context, req gen.RemoveMemberRequestObject) (gen.RemoveMemberResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.MemberManage); err != nil {
		return nil, err
	}
	m, err := h.targetMember(ctx, s, req.User)
	if err != nil {
		return nil, err
	}
	if s.p.Role != authz.Owner && authz.Role(m.Role).Rank() >= s.p.Role.Rank() {
		return nil, errForbidden("you can remove only members below your own role")
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID,
		Action: "member.remove", TargetKind: "user", TargetID: m.UserID, Metadata: map[string]any{"role": m.Role}},
		func(ev *store.AuditEvent) error { return h.d.Store.DeleteMember(ctx, s.tenant.ID, m.UserID, ev) })
	if err != nil {
		return nil, err
	}
	return gen.RemoveMember204Response{}, nil
}

func (h *Handlers) CreateMemberPasswordReset(ctx context.Context, req gen.CreateMemberPasswordResetRequestObject) (gen.CreateMemberPasswordResetResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	// Tenant owners generate reset links (core 7.2).
	if err := s.require(authz.TenantOwn); err != nil {
		return nil, err
	}
	if _, err := h.targetMember(ctx, s, req.User); err != nil {
		return nil, err
	}
	u, err := h.d.Store.GetUser(ctx, req.User)
	if err != nil {
		return nil, err
	}
	link, err := h.createResetLink(ctx, s.p, s.tenant.ID, u)
	if err != nil {
		return nil, err
	}
	return gen.CreateMemberPasswordReset201JSONResponse(link), nil
}

func invitationJSON(i store.Invitation) gen.Invitation {
	return gen.Invitation{Id: i.ID, Email: i.Email, Role: gen.Role(i.Role), ExpiresAt: i.ExpiresAt, AcceptedAt: i.AcceptedAt, CreatedAt: i.CreatedAt}
}

func (h *Handlers) ListInvitations(ctx context.Context, req gen.ListInvitationsRequestObject) (gen.ListInvitationsResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.MemberManage); err != nil {
		return nil, err
	}
	is, err := h.d.Store.ListInvitations(ctx, s.tenant.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Invitation, 0, len(is))
	for _, i := range is {
		out = append(out, invitationJSON(i))
	}
	return gen.ListInvitations200JSONResponse{Invitations: out}, nil
}

func (h *Handlers) CreateInvitation(ctx context.Context, req gen.CreateInvitationRequestObject) (gen.CreateInvitationResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.MemberManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("email", "email is required")
	}
	email, err := normalizeEmail(string(req.Body.Email))
	if err != nil {
		return nil, errInvalid("email", err.Error())
	}
	role := authz.Role(req.Body.Role)
	if !authz.ValidRole(string(role)) {
		return nil, errInvalid("role", "role must be owner, admin, member, or viewer")
	}
	if !authz.CanAssignRole(s.p.Role, authz.Viewer, role) {
		return nil, errForbidden("you can invite only roles below your own")
	}
	if u, err := h.d.Store.GetUserByEmail(ctx, email); err == nil {
		if _, err := h.d.Store.GetMembership(ctx, s.tenant.ID, u.ID); err == nil {
			return nil, errConflict("that user is already a member")
		}
	}
	tok := ids.RandomToken(32)
	now := h.now()
	inv := store.Invitation{ID: ids.New(), TenantID: s.tenant.ID, Email: email, Role: string(role), TokenHash: ids.HashToken(tok),
		ExpiresAt: now.Add(InvitationTTL), CreatedBy: s.p.ID, CreatedAt: now}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID,
		Action: "member.invite", TargetKind: "invitation", TargetID: inv.ID, Metadata: map[string]any{"email": email, "role": string(role)}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateInvitation(ctx, inv, ev) })
	if err != nil {
		return nil, err
	}
	return gen.CreateInvitation201JSONResponse{
		Invitation: invitationJSON(inv),
		Link:       gen.OneTimeLink{Token: tok, Url: h.baseURL(ctx) + "/invite/" + tok, ExpiresAt: inv.ExpiresAt},
	}, nil
}

// liveInvitation finds an unaccepted, unexpired invitation by token.
func (h *Handlers) liveInvitation(ctx context.Context, token string) (*store.Invitation, error) {
	inv, err := h.d.Store.GetInvitationByHash(ctx, ids.HashToken(token))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (inv.AcceptedAt != nil || !h.now().Before(inv.ExpiresAt))) {
		return nil, errNotFound("invitation")
	}
	return inv, err
}

func (h *Handlers) GetInvitation(ctx context.Context, req gen.GetInvitationRequestObject) (gen.GetInvitationResponseObject, error) {
	inv, err := h.liveInvitation(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	t, err := h.d.Store.GetTenant(ctx, inv.TenantID)
	if err != nil {
		return nil, err
	}
	_, uerr := h.d.Store.GetUserByEmail(ctx, inv.Email)
	return gen.GetInvitation200JSONResponse{TenantName: t.Name, Email: inv.Email, Role: gen.Role(inv.Role),
		ExistingUser: uerr == nil, ExpiresAt: inv.ExpiresAt}, nil
}

func (h *Handlers) AcceptInvitation(ctx context.Context, req gen.AcceptInvitationRequestObject) (gen.AcceptInvitationResponseObject, error) {
	inv, err := h.liveInvitation(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	now := h.now()
	existing, err := h.d.Store.GetUserByEmail(ctx, inv.Email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	m := store.Membership{TenantID: inv.TenantID, Role: inv.Role, CreatedAt: now}
	ev := audit.Event{ChainID: inv.TenantID, ActorKind: audit.ActorUser, Action: "member.join", TargetKind: "invitation",
		TargetID: inv.ID, Metadata: map[string]any{"email": inv.Email, "role": inv.Role}}

	if existing != nil {
		p := PrincipalFrom(ctx)
		if p == nil || p.Kind != authz.KindUser || p.ID != existing.ID || !p.Session.MFASatisfied {
			return nil, problem(401, "unauthorized", "sign in as "+inv.Email+" to accept this invitation")
		}
		m.UserID, ev.ActorID = existing.ID, existing.ID
		err = h.record(ctx, ev, func(e *store.AuditEvent) error { return h.d.Store.AcceptInvitation(ctx, *inv, nil, m, now, e) })
		if err != nil {
			return nil, err
		}
		return gen.AcceptInvitation200JSONResponse(h.loginOK(p)), nil
	}

	var fe fieldErrors
	name, pw := "", ""
	if req.Body != nil {
		name, pw = strings.TrimSpace(deref(req.Body.DisplayName)), deref(req.Body.Password)
	}
	if name == "" || len(name) > 128 {
		fe.add("display_name", "enter a name of at most 128 characters")
	}
	if err := authn.ValidatePassword(pw); err != nil {
		fe.add("password", err.Error())
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	u := store.User{ID: ids.New(), Email: inv.Email, DisplayName: name, CreatedAt: now, UpdatedAt: now}
	if u.PasswordHash, err = authn.HashPassword(pw); err != nil {
		return nil, err
	}
	m.UserID, ev.ActorID = u.ID, u.ID
	err = h.record(ctx, ev, func(e *store.AuditEvent) error { return h.d.Store.AcceptInvitation(ctx, *inv, &u, m, now, e) })
	if err != nil {
		return nil, err
	}
	// Sign the new user in; MFA enrollment comes next when it is required.
	satisfied := !h.d.Config.Auth.RequireMFA
	token := authn.NewWebSessionToken()
	sess := h.newSession(ctx, u.ID, token, store.SessionWeb, satisfied)
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: u.ID, Action: "auth.login",
		TargetKind: "user", TargetID: u.ID, Metadata: map[string]any{"session": sess.PublicID, "via": "invitation"}},
		func(e *store.AuditEvent) error { return h.d.Store.CreateSession(ctx, sess, e) })
	if err != nil {
		return nil, err
	}
	h.setSessionCookie(ctx, token, sess.ExpiresAt)
	status := gen.LoginResultStatusOk
	if !satisfied {
		status = gen.LoginResultStatusMfaEnrollmentRequired
	}
	return gen.AcceptInvitation200JSONResponse{Status: status, User: ptr(userJSON(&u))}, nil
}
