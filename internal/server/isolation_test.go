package server_test

import (
	"testing"

	"github.com/x6c-co/rypt-store/internal/server/servertest"
)

// TestTenantIsolation: a principal from tenant X gets 404 for every object
// in tenant Y (core 6.2, 16).
func TestTenantIsolation(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	c := a.Client
	c.Post("/api/v1/tenants", map[string]any{"name": "Other"}).Must(t, 201)
	other := "/api/v1/tenants/other"
	c.Post(other+"/projects", map[string]any{"name": "Secret Project"}).Must(t, 201)
	key := c.Post(other+"/projects/secret-project/environments/dev/secrets", map[string]any{"name": "KEY", "value": "v"}).
		Must(t, 201).Map()["id"].(string)
	m, _ := invite(t, e, c, a.Tenant, "member@example.com", "owner")

	p := other + "/projects/secret-project"
	paths := []struct{ method, path string }{
		{"GET", other}, {"GET", other + "/members"}, {"GET", other + "/invitations"}, {"POST", other + "/invitations"},
		{"GET", other + "/projects"}, {"POST", other + "/projects"}, {"GET", p}, {"PATCH", p}, {"DELETE", p},
		{"POST", p + "/key-mode"}, {"GET", p + "/environments"}, {"POST", p + "/environments"},
		{"PATCH", p + "/environments/dev"}, {"DELETE", p + "/environments/dev"},
		{"GET", other + "/audit"}, {"GET", other + "/audit/export"}, {"GET", other + "/audit/verify"},
		{"GET", p + "/compare"}, {"GET", p + "/environments/dev/secrets"}, {"POST", p + "/environments/dev/secrets"},
		{"GET", p + "/environments/dev/secrets/" + key}, {"PUT", p + "/environments/dev/secrets/" + key},
		{"DELETE", p + "/environments/dev/secrets/" + key}, {"GET", p + "/environments/dev/secrets/" + key + "/versions"},
		{"GET", p + "/environments/dev/secrets/" + key + "/versions/1"}, {"POST", p + "/environments/dev/secrets/" + key + "/versions/1/restore"},
		{"GET", p + "/environments/dev/secrets/deleted"}, {"POST", p + "/environments/dev/secrets/import"},
		{"GET", p + "/environments/dev/secrets/export"}, {"GET", p + "/environments/dev/secrets/values"},
		{"GET", p + "/tokens"}, {"POST", p + "/tokens"}, {"DELETE", p + "/tokens/0190a3c2-0000-7000-8000-000000000000"},
	}
	// The other tenant's secret ID under the member's own tenant and a
	// project with the same slug is 404 too.
	own := "/api/v1/tenants/" + a.Tenant + "/projects"
	c.Post(own, map[string]any{"name": "Secret Project"}).Must(t, 201)
	for _, m2 := range []string{"GET", "PUT", "DELETE"} {
		if r := m.Do(m2, own+"/secret-project/environments/dev/secrets/"+key, map[string]any{"value": "x"}, "If-Match", `"1"`); r.Status != 404 {
			t.Errorf("%s own path with a foreign secret ID: %d", m2, r.Status)
		}
	}
	for _, x := range paths {
		var body any
		if x.method != "GET" && x.method != "DELETE" {
			body = map[string]any{"name": "x", "value": "x", "email": "x@example.com", "role": "viewer", "key_mode": "C"}
		}
		r := m.Do(x.method, x.path, body, "If-Match", `"1"`)
		if r.Status != 404 {
			t.Errorf("%s %s: status %d, want 404 (%s)", x.method, x.path, r.Status, r.Body)
		}
	}
}
