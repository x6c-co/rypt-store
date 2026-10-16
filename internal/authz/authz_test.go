package authz

import (
	"testing"

	"github.com/x6c-co/rypt-store/internal/store"
)

// TestRoleTable covers every action for every role (core 7.5, 16).
func TestRoleTable(t *testing.T) {
	want := map[Action]map[Role]bool{
		SecretRead:     {Owner: true, Admin: true, Member: true, Viewer: true},
		SecretWrite:    {Owner: true, Admin: true, Member: true},
		ProjectManage:  {Owner: true, Admin: true},
		ProjectKeyMode: {Owner: true, Admin: true},
		TokenManage:    {Owner: true, Admin: true},
		MemberManage:   {Owner: true, Admin: true},
		AuditRead:      {Owner: true, Admin: true},
		TenantOwn:      {Owner: true},
		ProjectRead:    {Owner: true, Admin: true, Member: true, Viewer: true},
		InstanceManage: {},
	}
	res := Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "e1"}
	for _, a := range Actions {
		for _, r := range []Role{Owner, Admin, Member, Viewer} {
			p := &Principal{Kind: KindUser, ID: "u", TenantID: "t1", Role: r}
			if got := Can(p, a, res); got != want[a][r] {
				t.Errorf("%s %s: got %v, want %v", r, a, got, want[a][r])
			}
		}
	}
}

func TestTenantBoundary(t *testing.T) {
	p := &Principal{Kind: KindUser, ID: "u", TenantID: "t1", Role: Owner, IsInstanceAdmin: true}
	for _, a := range Actions {
		if a == InstanceManage {
			continue
		}
		if Can(p, a, Resource{TenantID: "t2"}) {
			t.Errorf("owner of t1 can %s in t2", a)
		}
	}
	// Instance admin without a membership gets nothing in a tenant.
	admin := &Principal{Kind: KindUser, ID: "u", IsInstanceAdmin: true}
	if Can(admin, SecretRead, Resource{TenantID: "t1"}) {
		t.Error("instance admin read secrets without membership")
	}
	if !Can(admin, InstanceManage, Resource{}) {
		t.Error("instance admin cannot manage the instance")
	}
	if Can(&Principal{Kind: KindUser, TenantID: "t1", Role: Owner}, InstanceManage, Resource{}) {
		t.Error("tenant owner can manage the instance")
	}
	if Can(nil, SecretRead, Resource{TenantID: "t1"}) {
		t.Error("nil principal allowed")
	}
}

func TestServiceTokenScope(t *testing.T) {
	scope := &TokenScope{TenantID: "t1", ProjectID: "p1", EnvironmentIDs: []string{"dev", "prod"}, Permission: store.TokenRead}
	tok := &Principal{Kind: KindServiceToken, ID: "tok", Scope: scope}
	cases := []struct {
		action Action
		res    Resource
		want   bool
	}{
		{SecretRead, Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "prod"}, true},
		{SecretRead, Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "staging"}, false},
		{SecretRead, Resource{TenantID: "t1", ProjectID: "p2", EnvironmentID: "prod"}, false},
		{SecretRead, Resource{TenantID: "t2", ProjectID: "p1", EnvironmentID: "prod"}, false},
		{SecretRead, Resource{TenantID: "t1", ProjectID: "p1"}, false},
		{SecretWrite, Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "prod"}, false},
		{ProjectRead, Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "prod"}, false},
		{TokenManage, Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "prod"}, false},
		{InstanceManage, Resource{}, false},
	}
	for i, c := range cases {
		if got := Can(tok, c.action, c.res); got != c.want {
			t.Errorf("case %d (%s %+v): got %v", i, c.action, c.res, got)
		}
	}
	scope.Permission = store.TokenReadWrite
	if !Can(tok, SecretWrite, Resource{TenantID: "t1", ProjectID: "p1", EnvironmentID: "dev"}) {
		t.Error("read_write token cannot write")
	}
}

func TestCanAssignRole(t *testing.T) {
	roles := []Role{Owner, Admin, Member, Viewer}
	for _, actor := range roles {
		for _, from := range roles {
			for _, to := range roles {
				got := CanAssignRole(actor, from, to)
				want := actor == Owner || (actor == Admin && from.Rank() <= 2 && to.Rank() <= 2)
				if got != want {
					t.Errorf("%s moving %s->%s: got %v", actor, from, to, got)
				}
			}
		}
	}
}
