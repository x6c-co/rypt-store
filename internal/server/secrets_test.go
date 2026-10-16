package server_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/server/servertest"
)

type fixture struct {
	e    *servertest.Env
	a    *servertest.Admin
	c    *servertest.Client
	proj string // .../projects/<slug>
}

func newFixture(t *testing.T, o servertest.Options, mode string) *fixture {
	t.Helper()
	e := servertest.Start(t, o)
	a := e.SetupAdmin()
	body := map[string]any{"name": "API"}
	if mode != "" {
		body["key_mode"] = mode
	}
	a.Client.Post("/api/v1/tenants/"+a.Tenant+"/projects", body).Must(t, 201)
	return &fixture{e: e, a: a, c: a.Client, proj: "/api/v1/tenants/" + a.Tenant + "/projects/api"}
}

func (f *fixture) env(e string) string { return f.proj + "/environments/" + e + "/secrets" }

// sec returns the path of the live secret named name in env, which
// addresses it by ID.
func (f *fixture) sec(t *testing.T, env, name string) string {
	t.Helper()
	var l struct {
		Secrets []struct {
			ID string `json:"id"`
		}
	}
	f.c.Get(f.env(env)+"?name="+name).Must(t, 200).JSON(&l)
	if len(l.Secrets) != 1 {
		t.Fatalf("no live secret %s in %s", name, env)
	}
	return f.env(env) + "/" + l.Secrets[0].ID
}

func TestSecretLifecycle(t *testing.T) {
	f := newFixture(t, servertest.Options{}, "")
	c, dev := f.c, f.env("dev")

	r := c.Post(dev, map[string]any{"name": "DATABASE_URL", "value": "postgres://one", "comment": "primary"}).Must(t, 201)
	if r.Header.Get("ETag") != `"1"` || r.Map()["version"] != float64(1) || r.Map()["value"] != nil {
		t.Fatalf("create = %s %v", r.Body, r.Header)
	}
	c.Post(dev, map[string]any{"name": "DATABASE_URL", "value": "x"}).Must(t, 409)
	c.Post(dev, map[string]any{"name": "bad-name", "value": "x"}).Must(t, 400)
	// Names are not in paths, so no name is reserved.
	r = c.Post(dev, map[string]any{"name": "values", "value": "not reserved"}).Must(t, 201)
	if v := c.Get(dev+"/"+r.Map()["id"].(string)).Must(t, 200).Map(); v["value"] != "not reserved" || v["name"] != "values" {
		t.Fatalf("secret named values = %v", v)
	}
	// The name filter finds one secret or none; paths take only UUIDs; an ID
	// from another environment is 404 here.
	var found struct{ Secrets []map[string]any }
	c.Get(dev+"?name=NOPE").Must(t, 200).JSON(&found)
	if len(found.Secrets) != 0 {
		t.Fatalf("filter for a missing name = %v", found)
	}
	c.Get(dev+"/DATABASE_URL").Must(t, 400)
	prodID := c.Post(f.env("prod"), map[string]any{"name": "PROD_ONLY", "value": "p"}).Must(t, 201).Map()["id"].(string)
	c.Get(dev+"/"+prodID).Must(t, 404)
	c.Get(f.env("prod")+"/"+prodID).Must(t, 200)

	// Read: value, ETag, no-store.
	r = c.Get(f.sec(t, "dev", "DATABASE_URL")).Must(t, 200)
	if r.Map()["value"] != "postgres://one" || r.Header.Get("ETag") != `"1"` || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("read = %s %v", r.Body, r.Header)
	}
	if by := r.Map()["updated_by"].(map[string]any); by["display"] != "Ada Admin" {
		t.Fatalf("updated_by = %v", by)
	}
	// Update with the right and a stale If-Match.
	c.Do("PUT", f.sec(t, "dev", "DATABASE_URL"), map[string]any{"value": "postgres://two"}, "If-Match", `"1"`).Must(t, 200)
	if r := c.Do("PUT", f.sec(t, "dev", "DATABASE_URL"), map[string]any{"value": "postgres://stale"}, "If-Match", `"1"`); r.Status != 409 {
		t.Fatalf("stale If-Match: %d %s", r.Status, r.Body)
	}
	c.Do("PUT", f.sec(t, "dev", "DATABASE_URL"), map[string]any{"value": "x"}).Must(t, 400) // If-Match required
	r = c.Do("PUT", f.sec(t, "dev", "DATABASE_URL"), map[string]any{"value": "postgres://three", "comment": "rotated"}, "If-Match", `"2"`).Must(t, 200)
	if r.Header.Get("ETag") != `"3"` || r.Map()["comment"] != "rotated" {
		t.Fatalf("update = %s", r.Body)
	}

	// History has no values; an old version reads back; restore makes v4.
	r = c.Get(f.sec(t, "dev", "DATABASE_URL")+"/versions").Must(t, 200)
	if strings.Contains(string(r.Body), "postgres://") {
		t.Fatalf("history leaked values: %s", r.Body)
	}
	var hist struct{ Versions []struct{ Version int } }
	r.JSON(&hist)
	if len(hist.Versions) != 3 || hist.Versions[0].Version != 3 {
		t.Fatalf("history = %s", r.Body)
	}
	if v := c.Get(f.sec(t, "dev", "DATABASE_URL")+"/versions/1").Must(t, 200).Map(); v["value"] != "postgres://one" || v["current"] != false {
		t.Fatalf("version 1 = %v", v)
	}
	c.Get(f.sec(t, "dev", "DATABASE_URL")+"/versions/9").Must(t, 404)
	r = c.Post(f.sec(t, "dev", "DATABASE_URL")+"/versions/1/restore", nil).Must(t, 200)
	if r.Header.Get("ETag") != `"4"` {
		t.Fatalf("restore etag = %s", r.Header.Get("ETag"))
	}
	if v := c.Get(f.sec(t, "dev", "DATABASE_URL")).Map(); v["value"] != "postgres://one" {
		t.Fatalf("after restore = %v", v)
	}
	r = c.Get(f.sec(t, "dev", "DATABASE_URL")+"/versions").Must(t, 200)
	if !strings.Contains(string(r.Body), `"restored_from":1`) {
		t.Fatalf("restored_from missing: %s", r.Body)
	}

	// Delete, recently deleted, name reuse, restore conflict, restore.
	orig := f.sec(t, "dev", "DATABASE_URL")
	c.Delete(orig).Must(t, 204)
	c.Get(orig).Must(t, 404)
	var del struct {
		Secrets []struct {
			ID   string `json:"id"`
			Name string
		}
	}
	c.Get(dev+"/deleted").Must(t, 200).JSON(&del)
	if len(del.Secrets) != 1 {
		t.Fatalf("deleted = %+v", del)
	}
	c.Post(dev, map[string]any{"name": "DATABASE_URL", "value": "new"}).Must(t, 201)
	c.Post(dev+"/deleted/"+del.Secrets[0].ID+"/restore", nil).Must(t, 409)
	c.Delete(f.sec(t, "dev", "DATABASE_URL")).Must(t, 204)
	c.Post(dev+"/deleted/"+del.Secrets[0].ID+"/restore", nil).Must(t, 200)
	if v := c.Get(f.sec(t, "dev", "DATABASE_URL")).Map(); v["value"] != "postgres://one" || v["version"] != float64(4) {
		t.Fatalf("restored = %v", v)
	}
	// Restoring keeps the secret's ID.
	if f.sec(t, "dev", "DATABASE_URL") != orig {
		t.Fatal("restored secret has a new ID")
	}

	// Every read and write is on the audit chain.
	var page struct{ Events []struct{ Action string } }
	c.Get("/api/v1/tenants/"+f.a.Tenant+"/audit?limit=500").Must(t, 200).JSON(&page)
	counts := map[string]int{}
	for _, ev := range page.Events {
		counts[ev.Action]++
	}
	for action, n := range map[string]int{"secret.create": 2, "secret.update": 2, "secret.read": 4, "secret.version.restore": 1,
		"secret.delete": 2, "secret.restore": 1} {
		if counts[action] < n {
			t.Errorf("audit %s = %d, want >= %d (%v)", action, counts[action], n, counts)
		}
	}
	if v := c.Get("/api/v1/tenants/" + f.a.Tenant + "/audit/verify").Map(); v["ok"] != true {
		t.Fatalf("verify = %v", v)
	}
}

func TestPruning(t *testing.T) {
	f := newFixture(t, servertest.Options{Config: func(c *config.Config) { c.Secrets.VersionsKept = 2 }}, "")
	dev := f.env("dev")
	f.c.Post(dev, map[string]any{"name": "K", "value": "v1"}).Must(t, 201)
	for i := 2; i <= 4; i++ {
		f.c.Do("PUT", f.sec(t, "dev", "K"), map[string]any{"value": "v" + string(rune('0'+i))}, "If-Match", `"`+string(rune('0'+i-1))+`"`).Must(t, 200)
	}
	f.e.App.Jobs.RunOnce(context.Background())
	var hist struct{ Versions []struct{ Version int } }
	f.c.Get(f.sec(t, "dev", "K")+"/versions").Must(t, 200).JSON(&hist)
	if len(hist.Versions) != 2 || hist.Versions[1].Version != 3 {
		t.Fatalf("after prune = %+v", hist)
	}
	f.c.Get(f.sec(t, "dev", "K")+"/versions/1").Must(t, 404)
	f.c.Get(f.sec(t, "dev", "K")+"/versions/3").Must(t, 200)
	// The pruned versions' DEK wraps are gone too.
	ctx := context.Background()
	s, _ := f.e.Store.GetTenantBySlug(ctx, f.a.Tenant)
	p, _ := f.e.Store.GetProjectBySlug(ctx, s.ID, "api")
	n, err := f.e.Store.CountProjectDEKs(ctx, p.ID)
	if err != nil || n != 2 {
		t.Fatalf("DEK wraps after prune = %d %v", n, err)
	}
	var page struct{ Events []struct{ Action string } }
	f.c.Get("/api/v1/tenants/"+f.a.Tenant+"/audit?action=secret.versions.pruned").Must(t, 200).JSON(&page)
	if len(page.Events) != 1 {
		t.Fatalf("pruned events = %+v", page)
	}
}

func TestPurge(t *testing.T) {
	f := newFixture(t, servertest.Options{}, "")
	dev := f.env("dev")
	f.c.Post(dev, map[string]any{"name": "OLD", "value": "v"}).Must(t, 201)
	f.c.Delete(f.sec(t, "dev", "OLD")).Must(t, 204)
	// Purge runs with the real clock; move the deletion into the past.
	ctx := context.Background()
	ten, _ := f.e.Store.GetTenantBySlug(ctx, f.a.Tenant)
	pr, _ := f.e.Store.GetProjectBySlug(ctx, ten.ID, "api")
	env, _ := f.e.Store.GetEnvironmentBySlug(ctx, ten.ID, pr.ID, "dev")
	del, _ := f.e.Store.ListDeletedSecrets(ctx, ten.ID, env.ID)
	if err := f.e.Store.SoftDeleteSecret(ctx, ten.ID, del[0].ID, time.Now(), nil); err == nil {
		t.Fatal("double soft delete accepted")
	}
	if err := f.e.App.Secrets.PurgeSweep(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.e.Store.ListDeletedSecrets(ctx, ten.ID, env.ID); len(d) != 1 {
		t.Fatalf("purged too early: %v", d)
	}
}

func TestCompare(t *testing.T) {
	f := newFixture(t, servertest.Options{}, "")
	c := f.c
	c.Post(f.env("dev"), map[string]any{"name": "SAME", "value": "shared"}).Must(t, 201)
	c.Post(f.env("staging"), map[string]any{"name": "SAME", "value": "shared"}).Must(t, 201)
	c.Post(f.env("prod"), map[string]any{"name": "SAME", "value": "different"}).Must(t, 201)
	c.Post(f.env("dev"), map[string]any{"name": "ONLY_DEV", "value": "x"}).Must(t, 201)
	c.Post(f.env("dev"), map[string]any{"name": "ALL_EQUAL", "value": "e"}).Must(t, 201)
	c.Post(f.env("staging"), map[string]any{"name": "ALL_EQUAL", "value": "e"}).Must(t, 201)
	c.Post(f.env("prod"), map[string]any{"name": "ALL_EQUAL", "value": "e"}).Must(t, 201)

	r := c.Get(f.proj+"/compare").Must(t, 200)
	for _, leak := range []string{"shared", "different", `"e"`, "mac", "value"} {
		if strings.Contains(string(r.Body), leak) {
			t.Fatalf("compare leaked %q: %s", leak, r.Body)
		}
	}
	var grid struct {
		Environments []struct{ Slug string }
		Rows         []struct {
			Name  string
			Cells []struct {
				Environment string
				Missing     bool
				Group       *int
				Secret      *string
			}
		}
	}
	r.JSON(&grid)
	got := map[string]string{}
	for _, row := range grid.Rows {
		var b strings.Builder
		for _, cell := range row.Cells {
			// Each present cell names the secret to open in that environment.
			if (cell.Secret == nil) != cell.Missing || (cell.Secret != nil && f.sec(t, cell.Environment, row.Name) != f.env(cell.Environment)+"/"+*cell.Secret) {
				t.Fatalf("%s/%s secret = %v", row.Name, cell.Environment, cell.Secret)
			}
			if cell.Missing {
				b.WriteString("-")
			} else {
				b.WriteString(string(rune('0' + *cell.Group)))
			}
		}
		got[row.Name] = b.String()
	}
	want := map[string]string{"SAME": "112", "ONLY_DEV": "1--", "ALL_EQUAL": "111"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	// Compare reads no values, so it writes no read events.
	var page struct{ Events []struct{ Action string } }
	c.Get("/api/v1/tenants/"+f.a.Tenant+"/audit?action=secret.read").Must(t, 200).JSON(&page)
	if len(page.Events) != 0 {
		t.Fatalf("compare audited reads: %+v", page)
	}
}

func TestImportExport(t *testing.T) {
	f := newFixture(t, servertest.Options{}, "")
	dev := f.env("dev")
	f.c.Post(dev, map[string]any{"name": "EXISTING", "value": "old"}).Must(t, 201)
	src := "EXISTING=new\nNEW_ONE=\"multi\nline\"\nexport PLAIN=p # c\n1BAD=x\n"
	r := f.c.Do("POST", dev+"/import", src).Must(t, 200)
	var res struct {
		Created, Updated, Skipped []string
		Rejected                  []struct {
			Name string
			Line int
		}
	}
	r.JSON(&res)
	if strings.Join(res.Created, ",") != "NEW_ONE,PLAIN" || strings.Join(res.Skipped, ",") != "EXISTING" ||
		len(res.Rejected) != 1 || res.Rejected[0].Line != 5 {
		t.Fatalf("import = %s", r.Body)
	}
	r = f.c.Do("POST", dev+"/import?mode=overwrite", src).Must(t, 200)
	r.JSON(&res)
	if strings.Join(res.Updated, ",") != "EXISTING" || len(res.Skipped) != 2 {
		t.Fatalf("overwrite = %s", r.Body)
	}
	r = f.c.Get(dev+"/export").Must(t, 200)
	if !strings.Contains(string(r.Body), `NEW_ONE="multi\nline"`) || !strings.Contains(string(r.Body), `EXISTING="new"`) {
		t.Fatalf("dotenv export = %s", r.Body)
	}
	var vals map[string]string
	f.c.Get(dev+"/export?format=json").Must(t, 200).JSON(&vals)
	if vals["NEW_ONE"] != "multi\nline" || len(vals) != 3 {
		t.Fatalf("json export = %v", vals)
	}
	var bulk struct{ Values map[string]string }
	f.c.Get(dev+"/values").Must(t, 200).JSON(&bulk)
	if bulk.Values["PLAIN"] != "p" {
		t.Fatalf("values = %v", bulk)
	}
	var page struct {
		Events []struct {
			Action   string
			Metadata map[string]any
		}
	}
	f.c.Get("/api/v1/tenants/"+f.a.Tenant+"/audit?action=secret.").Must(t, 200).JSON(&page)
	bulkEvents, imports := 0, 0
	for _, ev := range page.Events {
		switch ev.Action {
		case "secret.read.bulk":
			bulkEvents++
			if ids, _ := ev.Metadata["secret_ids"].([]any); len(ids) != 3 {
				t.Errorf("bulk read lists %d secret ids", len(ids))
			}
		case "secret.import":
			imports++
		case "secret.read":
			t.Errorf("bulk read wrote a per-secret read event")
		}
	}
	if bulkEvents != 3 || imports != 2 {
		t.Fatalf("bulk events = %d, imports = %d", bulkEvents, imports)
	}
}

func createToken(t *testing.T, f *fixture, name, perm string, envs []string, expires time.Time) (string, string) {
	t.Helper()
	r := f.c.Post(f.proj+"/tokens", map[string]any{"name": name, "environments": envs, "permission": perm,
		"expires_at": expires.UTC().Format(time.RFC3339)}).Must(t, 201)
	var out struct {
		Token struct {
			ID     string `json:"id"`
			Prefix string
		}
		Secret string
	}
	r.JSON(&out)
	if !strings.HasPrefix(out.Secret, "rst_") || !strings.Contains(out.Secret, out.Token.Prefix) {
		t.Fatalf("token = %s", r.Body)
	}
	return out.Token.ID, out.Secret
}

func TestServiceTokenScope(t *testing.T) {
	f := newFixture(t, servertest.Options{}, "")
	f.c.Post(f.env("prod"), map[string]any{"name": "API_KEY", "value": "prod-key"}).Must(t, 201)
	f.c.Post(f.env("dev"), map[string]any{"name": "API_KEY", "value": "dev-key"}).Must(t, 201)
	f.c.Post("/api/v1/tenants/"+f.a.Tenant+"/projects", map[string]any{"name": "Other"}).Must(t, 201)
	other := "/api/v1/tenants/" + f.a.Tenant + "/projects/other/environments/prod/secrets"

	_, readTok := createToken(t, f, "ci", "read", []string{"prod"}, time.Now().Add(24*time.Hour))
	tc := f.e.BearerClient(readTok)
	// A read token reads prod and gets 404 for a write (acceptance 3).
	if v := tc.Get(f.sec(t, "prod", "API_KEY")).Must(t, 200).Map(); v["value"] != "prod-key" {
		t.Fatalf("token read = %v", v)
	}
	tc.Get(f.env("prod")).Must(t, 200)
	tc.Get(f.env("prod")+"/values").Must(t, 200)
	tc.Do("PUT", f.sec(t, "prod", "API_KEY"), map[string]any{"value": "x"}, "If-Match", `"1"`).Must(t, 404)
	tc.Post(f.env("prod"), map[string]any{"name": "NEW", "value": "x"}).Must(t, 404)
	// Wrong environment, wrong project, and non-secret paths are 404.
	tc.Get(f.sec(t, "dev", "API_KEY")).Must(t, 404)
	tc.Get(other).Must(t, 404)
	tc.Get(f.proj).Must(t, 404)
	tc.Get(f.proj+"/compare").Must(t, 404)
	tc.Get("/api/v1/tenants/"+f.a.Tenant+"/projects").Must(t, 404)
	tc.Get("/api/v1/tenants").Must(t, 404)
	// /me describes the token's scope for the CLI.
	me := tc.Get("/api/v1/me").Must(t, 200).Map()
	if tok := me["token"].(map[string]any); tok["project"] != "api" || tok["permission"] != "read" {
		t.Fatalf("token me = %v", me)
	}

	// A read_write token writes.
	_, rwTok := createToken(t, f, "deploy", "read_write", []string{"dev"}, time.Now().Add(time.Hour))
	f.e.BearerClient(rwTok).Do("PUT", f.sec(t, "dev", "API_KEY"), map[string]any{"value": "rotated"}, "If-Match", `"1"`).Must(t, 200)

	// Revoked and expired tokens are 401 and audited as token.denied.
	revID, revTok := createToken(t, f, "temp", "read", []string{"prod"}, time.Now().Add(time.Hour))
	f.c.Delete(f.proj+"/tokens/"+revID).Must(t, 204)
	f.e.BearerClient(revTok).Get(f.sec(t, "prod", "API_KEY")).Must(t, 401)
	_, expTok := createToken(t, f, "short", "read", []string{"prod"}, time.Now().Add(time.Minute))
	f.e.Clock.Advance(2 * time.Minute)
	f.e.BearerClient(expTok).Get(f.sec(t, "prod", "API_KEY")).Must(t, 401)
	f.e.BearerClient(readTok[:len(readTok)-1]+"x").Get(f.env("prod")).Must(t, 401)
	var page struct {
		Events []struct{ Metadata map[string]any }
	}
	f.c.Get("/api/v1/tenants/"+f.a.Tenant+"/audit?action=token.denied").Must(t, 200).JSON(&page)
	reasons := map[string]bool{}
	for _, ev := range page.Events {
		reasons[ev.Metadata["reason"].(string)] = true
	}
	if !reasons["revoked"] || !reasons["expired"] || !reasons["wrong secret"] {
		t.Fatalf("token.denied reasons = %v", reasons)
	}

	// Validation: expiry beyond max_ttl, unknown environment, past expiry.
	for _, body := range []map[string]any{
		{"name": "x", "environments": []string{"prod"}, "permission": "read", "expires_at": time.Now().Add(400 * 24 * time.Hour).Format(time.RFC3339)},
		{"name": "x", "environments": []string{"nope"}, "permission": "read", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)},
		{"name": "x", "environments": []string{"prod"}, "permission": "read", "expires_at": time.Now().Add(-time.Hour).Format(time.RFC3339)},
	} {
		f.c.Post(f.proj+"/tokens", body).Must(t, 400)
	}
	var list struct{ Tokens []json.RawMessage }
	f.c.Get(f.proj+"/tokens").Must(t, 200).JSON(&list)
	if len(list.Tokens) != 4 {
		t.Fatalf("tokens = %d", len(list.Tokens))
	}
}

// TestModeCProviderCalls checks provider operations through the API with
// the fake rypt provider: one wrap per write, one unwrap per secret on a
// cold bulk read, none when warm (feature 01 8).
func TestModeCProviderCalls(t *testing.T) {
	f := newFixture(t, servertest.Options{Config: func(c *config.Config) {
		c.Keys.Provider = "rypt"
		c.Rypt.Token, c.Rypt.KeyID = "ry_test", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	}}, "C")
	dev := f.env("dev")
	f.e.Rypt.Reset()
	for _, n := range []string{"A", "B", "C"} {
		f.c.Post(dev, map[string]any{"name": n, "value": "v"}).Must(t, 201)
	}
	if n := f.e.Rypt.Calls("wrap"); n != 3 {
		t.Fatalf("writes made %d wraps", n)
	}
	f.e.Rypt.Reset()
	f.c.Get(dev+"/values").Must(t, 200)
	if n := f.e.Rypt.Total(); n != 0 {
		t.Fatalf("warm bulk read made %d provider calls", n)
	}
	// A restarted server has a cold cache.
	e2 := servertest.Start(t, servertest.Options{Store: f.e.Store, Rypt: f.e.Rypt, Clock: f.e.Clock, Config: func(c *config.Config) {
		c.Keys.Provider = "rypt"
		c.Rypt.Token, c.Rypt.KeyID = "ry_test", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	}})
	f.e.Rypt.Reset()
	c2 := e2.Login(f.a.Email, f.a.Password, f.a.TOTPSecret)
	base := f.e.Rypt.Total() // the IK unwrap for TOTP at login
	c2.Get(dev+"/values").Must(t, 200)
	if n := f.e.Rypt.Total() - base; n != 3 {
		t.Fatalf("cold bulk read made %d provider calls, want 3", n)
	}
	before := f.e.Rypt.Total()
	c2.Get(f.sec(t, "dev", "A")).Must(t, 200)
	if n := f.e.Rypt.Total() - before; n != 0 {
		t.Fatalf("warm single read made %d calls", n)
	}

	// An outage under fail_closed is a 503 with key_provider_unavailable.
	e3 := servertest.Start(t, servertest.Options{Store: f.e.Store, Rypt: f.e.Rypt, Clock: f.e.Clock, Config: func(c *config.Config) {
		c.Keys.Provider = "rypt"
		c.Rypt.Token, c.Rypt.KeyID = "ry_test", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	}})
	c3 := e3.Login(f.a.Email, f.a.Password, f.a.TOTPSecret)
	f.e.Rypt.Fail(f.e.Rypt.OutageError)
	if r := c3.Get(f.sec(t, "dev", "B")); r.Status != 503 || r.Code() != "key_provider_unavailable" {
		t.Fatalf("outage: %d %s", r.Status, r.Body)
	}
	f.e.Rypt.Fail(f.e.Rypt.QuotaError)
	if r := c3.Get(f.sec(t, "dev", "C")); r.Status != 503 || r.Code() != "key_provider_quota" {
		t.Fatalf("quota: %d %s", r.Status, r.Body)
	}
	f.e.Rypt.Fail(nil)
	if q := c3.Get("/api/v1/me").Map()["notices"].(map[string]any)["provider_quota"]; q == nil {
		t.Fatal("quota notice missing")
	}
}
