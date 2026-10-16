package server_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/server/servertest"
)

// member signs up through an invitation and enrolls TOTP.
func invite(t *testing.T, e *servertest.Env, inviter *servertest.Client, tenant, email, role string) (*servertest.Client, string) {
	t.Helper()
	r := inviter.Post("/api/v1/tenants/"+tenant+"/invitations", map[string]any{"email": email, "role": role}).Must(t, 201)
	tok := r.Map()["link"].(map[string]any)["token"].(string)
	c := e.Client()
	pre := c.Get("/api/v1/auth/invitations/"+tok).Must(t, 200).Map()
	if pre["existing_user"] != false || pre["role"] != role {
		t.Fatalf("invitation preview = %v", pre)
	}
	r = c.Post("/api/v1/auth/invitations/"+tok+"/accept", map[string]any{"display_name": "New Person", "password": "member password 123"}).Must(t, 200)
	if r.Map()["status"] != "mfa_enrollment_required" {
		t.Fatalf("accept = %s", r.Body)
	}
	if r := c.Get("/api/v1/tenants"); r.Code() != "mfa_enrollment_required" {
		t.Fatalf("before enrollment: %s", r.Body)
	}
	secret := c.Post("/api/v1/me/mfa/totp", nil).Must(t, 200).Map()["secret"].(string)
	c.Post("/api/v1/me/mfa/totp/confirm", map[string]any{"code": e.TOTPCode(secret)}).Must(t, 200)
	return c, secret
}

func TestProjectsAndEnvironments(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	c := a.Client
	base := "/api/v1/tenants/" + a.Tenant

	r := c.Post(base+"/projects", map[string]any{"name": "Billing API"}).Must(t, 201)
	var p struct {
		Slug         string
		KeyMode      string `json:"key_mode"`
		Environments []struct{ Slug string }
	}
	r.JSON(&p)
	if p.Slug != "billing-api" || p.KeyMode != "B" || len(p.Environments) != 3 || p.Environments[2].Slug != "prod" {
		t.Fatalf("project = %s", r.Body)
	}
	c.Post(base+"/projects", map[string]any{"name": "Web", "key_mode": "C"}).Must(t, 201)
	if r := c.Post(base+"/projects", map[string]any{"name": "Billing API"}); r.Status != 409 {
		t.Fatalf("duplicate slug: %d", r.Status)
	}
	if r := c.Post(base+"/projects", map[string]any{"name": "X", "key_mode": "Z"}); r.Status != 400 {
		t.Fatalf("bad mode: %d", r.Status)
	}
	var list struct{ Projects []struct{ Slug string } }
	c.Get(base+"/projects").Must(t, 200).JSON(&list)
	if len(list.Projects) != 2 {
		t.Fatalf("projects = %+v", list)
	}
	c.Patch(base+"/projects/billing-api", map[string]any{"name": "Billing", "slug": "billing"}).Must(t, 200)
	c.Get(base+"/projects/billing").Must(t, 200)
	c.Get(base+"/projects/billing-api").Must(t, 404)

	pb := base + "/projects/billing"
	r = c.Post(pb+"/environments", map[string]any{"name": "QA"}).Must(t, 201)
	if r.Map()["slug"] != "qa" || r.Map()["position"] != float64(3) {
		t.Fatalf("env = %s", r.Body)
	}
	c.Patch(pb+"/environments/qa", map[string]any{"name": "Quality", "position": 1}).Must(t, 200)
	if r := c.Post(pb+"/environments", map[string]any{"name": "dev"}); r.Status != 409 {
		t.Fatalf("duplicate env: %d", r.Status)
	}
	c.Delete(pb+"/environments/qa").Must(t, 204)
	c.Patch(pb+"/environments/qa", map[string]any{"name": "x"}).Must(t, 404)
	c.Delete(base+"/projects/web").Must(t, 204)
	c.Get(base+"/projects/web").Must(t, 404)
	// A deleted project's slug can be reused.
	c.Post(base+"/projects", map[string]any{"name": "Web"}).Must(t, 201)
}

func TestMembersAndRoles(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	base := "/api/v1/tenants/" + a.Tenant
	admin2, _ := invite(t, e, a.Client, a.Tenant, "admin2@example.com", "admin")
	member, _ := invite(t, e, a.Client, a.Tenant, "member@example.com", "member")
	viewer, _ := invite(t, e, admin2, a.Tenant, "viewer@example.com", "viewer")

	var ms struct {
		Members []struct {
			UserID string `json:"user_id"`
			Email  string
			Role   string
		}
	}
	member.Get(base+"/members").Must(t, 200).JSON(&ms)
	if len(ms.Members) != 4 {
		t.Fatalf("members = %+v", ms)
	}
	ids := map[string]string{}
	for _, m := range ms.Members {
		ids[m.Email] = m.UserID
	}
	// Members cannot manage projects or members.
	member.Post(base+"/projects", map[string]any{"name": "Nope"}).Must(t, 403)
	member.Post(base+"/invitations", map[string]any{"email": "x@example.com", "role": "viewer"}).Must(t, 403)
	viewer.Get(base+"/audit").Must(t, 403)
	// Admins change only roles below their own and cannot mint owners.
	admin2.Patch(base+"/members/"+ids["member@example.com"], map[string]any{"role": "viewer"}).Must(t, 200)
	admin2.Patch(base+"/members/"+ids["viewer@example.com"], map[string]any{"role": "owner"}).Must(t, 403)
	admin2.Patch(base+"/members/"+ids["admin@example.com"], map[string]any{"role": "member"}).Must(t, 403)
	admin2.Post(base+"/invitations", map[string]any{"email": "o@example.com", "role": "owner"}).Must(t, 403)
	// The owner can; the last owner cannot step down.
	a.Client.Patch(base+"/members/"+ids["admin@example.com"], map[string]any{"role": "admin"}).Must(t, 409)
	a.Client.Patch(base+"/members/"+ids["admin2@example.com"], map[string]any{"role": "owner"}).Must(t, 200)
	a.Client.Patch(base+"/members/"+ids["admin@example.com"], map[string]any{"role": "admin"}).Must(t, 200)
	// Removal.
	admin2.Delete(base+"/members/"+ids["viewer@example.com"]).Must(t, 204)
	if r := viewer.Get(base + "/projects"); r.Status != 404 {
		t.Fatalf("removed member still sees the tenant: %d", r.Status)
	}
	// An invitation for an existing member is refused.
	admin2.Post(base+"/invitations", map[string]any{"email": "member@example.com", "role": "viewer"}).Must(t, 409)
}

func TestPasswordResetLink(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	m, secret := invite(t, e, a.Client, a.Tenant, "member@example.com", "member")
	var me struct{ User struct{ ID string } }
	m.Get("/api/v1/me").Must(t, 200).JSON(&me)
	r := a.Client.Post("/api/v1/tenants/"+a.Tenant+"/members/"+me.User.ID+"/password-reset", nil).Must(t, 201)
	link := r.Map()
	if !strings.Contains(link["url"].(string), "/reset-password/") {
		t.Fatalf("link = %v", link)
	}
	tok := link["token"].(string)
	e.Client().Post("/api/v1/auth/password-reset", map[string]any{"token": tok, "new_password": "brand new password"}).Must(t, 204)
	// Old sessions are revoked; the link is single use; the new password works.
	m.Get("/api/v1/me").Must(t, 401)
	e.Client().Post("/api/v1/auth/password-reset", map[string]any{"token": tok, "new_password": "another password!"}).Must(t, 400)
	e.Login("member@example.com", "brand new password", secret)
	// Non-owners cannot generate links.
	m2 := e.Login("member@example.com", "brand new password", secret)
	m2.Post("/api/v1/tenants/"+a.Tenant+"/members/"+me.User.ID+"/password-reset", nil).Must(t, 403)
}

func TestAuditEndpoints(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	c := a.Client
	base := "/api/v1/tenants/" + a.Tenant
	c.Post(base+"/projects", map[string]any{"name": "API"}).Must(t, 201)
	c.Post(base+"/projects/api/environments", map[string]any{"name": "QA"}).Must(t, 201)

	var page struct {
		Events []struct {
			Seq          int64
			Action       string
			ActorDisplay *string `json:"actor_display"`
		}
		Head struct {
			Seq  int64
			Hash string
		}
		NextCursor *string `json:"next_cursor"`
	}
	c.Get(base+"/audit?limit=1").Must(t, 200).JSON(&page)
	if len(page.Events) != 1 || page.Events[0].Action != "environment.create" || page.NextCursor == nil || page.Head.Seq != 2 {
		t.Fatalf("audit page = %+v", page)
	}
	if page.Events[0].ActorDisplay == nil || *page.Events[0].ActorDisplay != "Ada Admin" {
		t.Fatalf("actor display = %v", page.Events[0].ActorDisplay)
	}
	c.Get(base+"/audit?cursor="+*page.NextCursor).Must(t, 200).JSON(&page)
	if len(page.Events) != 1 || page.Events[0].Action != "project.create" {
		t.Fatalf("second page = %+v", page)
	}
	c.Get(base+"/audit?action=project.").Must(t, 200).JSON(&page)
	if len(page.Events) != 1 {
		t.Fatalf("filtered = %+v", page)
	}
	v := c.Get(base+"/audit/verify").Must(t, 200).Map()
	if v["ok"] != true {
		t.Fatalf("verify = %v", v)
	}
	r := c.Get(base+"/audit/export").Must(t, 200)
	if !strings.Contains(r.Header.Get("Content-Type"), "jsonl") {
		t.Fatalf("export content type = %s", r.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(bytes.NewReader(r.Body))
	prev := audit.ZeroHash
	lines := 0
	for sc.Scan() {
		var x audit.ExportedEvent
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			t.Fatal(err)
		}
		ev := audit.FromExported(x)
		h, _ := audit.Hash(ev)
		if ev.PrevHash != prev || h != ev.Hash {
			t.Fatalf("export line %d does not verify", lines+1)
		}
		prev = ev.Hash
		lines++
	}
	if lines != 3 { // project.create, environment.create, audit.export
		t.Fatalf("export lines = %d", lines)
	}

	// Instance chain: setup, logins, tenant creation.
	inst := c.Get("/api/v1/instance/audit?action=setup.").Must(t, 200)
	if !strings.Contains(string(inst.Body), `"setup.complete"`) {
		t.Fatalf("instance audit = %s", inst.Body)
	}
	if v := c.Get("/api/v1/instance/audit/verify").Must(t, 200).Map(); v["ok"] != true {
		t.Fatalf("instance verify = %v", v)
	}
}

func TestInstanceEndpoints(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	c := a.Client
	s := c.Get("/api/v1/instance/settings").Must(t, 200).Map()
	if s["provider"] != "local" || s["tls_mode"] != "self_signed" || s["versions_kept"] != float64(20) {
		t.Fatalf("settings = %v", s)
	}
	k := c.Get("/api/v1/instance/keys").Must(t, 200).Map()
	if k["provider"] != "local" || len(k["mode_costs"].([]any)) != 3 {
		t.Fatalf("keys = %v", k)
	}
	c.Get("/api/v1/instance/users").Must(t, 200)
	r := c.Post("/api/v1/tenants", map[string]any{"name": "Second Client"}).Must(t, 201)
	if r.Map()["slug"] != "second-client" || r.Map()["role"] != "owner" {
		t.Fatalf("tenant = %s", r.Body)
	}
	var ts struct{ Tenants []any }
	c.Get("/api/v1/tenants").Must(t, 200).JSON(&ts)
	if len(ts.Tenants) != 2 {
		t.Fatalf("tenants = %v", ts)
	}
	m, _ := invite(t, e, c, a.Tenant, "member@example.com", "member")
	m.Get("/api/v1/instance/settings").Must(t, 403)
	m.Get("/api/v1/tenants?scope=all").Must(t, 403)
	m.Post("/api/v1/tenants", map[string]any{"name": "Mine"}).Must(t, 403)
}
