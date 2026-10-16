package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	rqhttp "github.com/rqlite/rqlite-go-http"

	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
	"github.com/x6c-co/rypt-store/internal/store/storetest"
)

var ctx = context.Background()

func TestCanonical(t *testing.T) {
	got, err := Canonical(map[string]any{"b": 1, "a": map[string]any{"z": "<&>", "y": []any{2.5, nil}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":{"y":[2.5,null],"z":"<&>"},"b":1}` {
		t.Fatalf("canonical = %s", got)
	}
}

func TestHashCoversEveryField(t *testing.T) {
	base := store.AuditEvent{ID: "id", ChainID: "c", Seq: 1, TS: "2026-10-16T00:00:00.000Z", ActorKind: "user", ActorID: "u",
		Action: "secret.read", TargetKind: "secret", TargetID: "s", ProjectID: "p", EnvironmentID: "e", Result: "success",
		IP: "1.2.3.4", UserAgent: "ua", RequestID: "r", ProviderRequestID: "pr", Metadata: `{"k":"v"}`, PrevHash: ZeroHash}
	h0, _ := Hash(base)
	mutations := map[string]func(*store.AuditEvent){
		"id": func(e *store.AuditEvent) { e.ID = "x" }, "chain": func(e *store.AuditEvent) { e.ChainID = "x" },
		"seq": func(e *store.AuditEvent) { e.Seq = 2 }, "ts": func(e *store.AuditEvent) { e.TS = "x" },
		"actor_kind": func(e *store.AuditEvent) { e.ActorKind = "x" }, "actor_id": func(e *store.AuditEvent) { e.ActorID = "x" },
		"action": func(e *store.AuditEvent) { e.Action = "x" }, "target_kind": func(e *store.AuditEvent) { e.TargetKind = "x" },
		"target_id": func(e *store.AuditEvent) { e.TargetID = "x" }, "project": func(e *store.AuditEvent) { e.ProjectID = "x" },
		"env": func(e *store.AuditEvent) { e.EnvironmentID = "x" }, "result": func(e *store.AuditEvent) { e.Result = "x" },
		"ip": func(e *store.AuditEvent) { e.IP = "x" }, "ua": func(e *store.AuditEvent) { e.UserAgent = "x" },
		"request": func(e *store.AuditEvent) { e.RequestID = "x" }, "provider_request": func(e *store.AuditEvent) { e.ProviderRequestID = "x" },
		"metadata": func(e *store.AuditEvent) { e.Metadata = `{"k":"w"}` }, "prev": func(e *store.AuditEvent) { e.PrevHash = "x" },
	}
	for name, mut := range mutations {
		e := base
		mut(&e)
		if h, _ := Hash(e); h == h0 {
			t.Errorf("changing %s did not change the hash", name)
		}
	}
	// Metadata key order does not matter.
	e := base
	e.Metadata = `{ "k" : "v" }`
	if h, _ := Hash(e); h != h0 {
		t.Error("metadata whitespace changed the hash")
	}
}

type fixture struct {
	st  store.Store
	raw *rqhttp.Client
	w   *Writer
}

func setup(t *testing.T) *fixture {
	t.Helper()
	st, url := storetest.NewWithURL(t)
	raw, err := rqhttp.NewClient(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAuditChain(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, raw: raw, w: NewWriter(st, nil, nil)}
}

func (f *fixture) write(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		err := f.w.Record(WithRequestInfo(ctx, RequestInfo{IP: "10.0.0.1", RequestID: ids.New()}), Event{
			ChainID: "tenant-1", ActorKind: ActorUser, ActorID: "u1", Action: "secret.read",
			TargetKind: "secret", TargetID: fmt.Sprintf("s%d", i), Metadata: map[string]any{"i": i, "note": "<ok>"},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) sql(t *testing.T, q string, args ...any) {
	t.Helper()
	resp, err := f.raw.ExecuteSingle(ctx, q, args...)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyIntactChain(t *testing.T) {
	f := setup(t)
	f.write(t, 10)
	res, err := Verify(ctx, f.st, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	head, _ := f.st.GetAuditHead(ctx, "tenant-1")
	if !res.OK || res.Seq != 10 || res.Hash != head.HeadHash || res.Checked != 10 {
		t.Fatalf("verify = %+v", res)
	}
	if !strings.HasPrefix(res.String(), "OK 10 ") {
		t.Fatalf("string = %s", res)
	}
}

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, f *fixture)
		seq    int64
	}{
		{"modified field", func(t *testing.T, f *fixture) {
			f.sql(t, "UPDATE audit_events SET actor_id = 'mallory' WHERE chain_id = 'tenant-1' AND seq = 4")
		}, 4},
		{"modified metadata", func(t *testing.T, f *fixture) {
			f.sql(t, `UPDATE audit_events SET metadata = '{"i":99}' WHERE chain_id = 'tenant-1' AND seq = 6`)
		}, 6},
		{"deleted row", func(t *testing.T, f *fixture) {
			f.sql(t, "DELETE FROM audit_events WHERE chain_id = 'tenant-1' AND seq = 5")
		}, 5},
		{"deleted tail", func(t *testing.T, f *fixture) {
			f.sql(t, "DELETE FROM audit_events WHERE chain_id = 'tenant-1' AND seq >= 9")
		}, 9},
		{"reordered rows", func(t *testing.T, f *fixture) {
			f.sql(t, "UPDATE audit_events SET seq = -1 WHERE chain_id = 'tenant-1' AND seq = 3")
			f.sql(t, "UPDATE audit_events SET seq = 3 WHERE chain_id = 'tenant-1' AND seq = 7")
			f.sql(t, "UPDATE audit_events SET seq = 7 WHERE chain_id = 'tenant-1' AND seq = -1")
		}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			f.write(t, 10)
			c.tamper(t, f)
			res, err := Verify(ctx, f.st, "tenant-1")
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || res.Seq != c.seq {
				t.Fatalf("verify = %+v, want broken at %d", res, c.seq)
			}
		})
	}
}

func TestConcurrentWriters(t *testing.T) {
	f := setup(t)
	// Separate writers do not share the in-process mutex, like two processes;
	// the head guard keeps the chain gapless anyway.
	writers := []*Writer{NewWriter(f.st, nil, nil), NewWriter(f.st, nil, nil), NewWriter(f.st, nil, nil)}
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for _, w := range writers {
		for i := range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- w.Record(ctx, Event{ChainID: "tenant-1", ActorKind: ActorSystem, Action: "test.concurrent", Metadata: map[string]any{"i": i}}, nil)
			}()
		}
	}
	wg.Wait()
	close(errs)
	failed := 0
	for err := range errs {
		if err != nil {
			failed++
		}
	}
	head, _ := f.st.GetAuditHead(ctx, "tenant-1")
	if int(head.HeadSeq) != 30-failed {
		t.Fatalf("head = %d with %d failures", head.HeadSeq, failed)
	}
	if failed > 0 {
		t.Logf("%d writes exhausted their retries under contention", failed)
	}
	res, err := Verify(ctx, f.st, "tenant-1")
	if err != nil || !res.OK {
		t.Fatalf("verify after concurrent writes = %+v %v", res, err)
	}
}

func TestRetentionAnchoring(t *testing.T) {
	f := setup(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f.w.now = func() time.Time { return now }
	f.write(t, 5) // old events
	now = now.Add(40 * 24 * time.Hour)
	f.write(t, 3) // recent events
	n, err := f.w.Prune(ctx, "tenant-1", now.Add(-30*24*time.Hour))
	if err != nil || n != 5 {
		t.Fatalf("prune = %d %v", n, err)
	}
	head, _ := f.st.GetAuditHead(ctx, "tenant-1")
	if head.AnchorSeq != 5 || head.HeadSeq != 9 {
		t.Fatalf("head after prune = %+v", head)
	}
	res, err := Verify(ctx, f.st, "tenant-1")
	if err != nil || !res.OK || res.Checked != 4 || res.AnchorSeq != 5 {
		t.Fatalf("verify after prune = %+v %v", res, err)
	}
	last, _ := f.st.GetAuditEventBySeq(ctx, "tenant-1", 9)
	if last.Action != "audit.pruned" || !strings.Contains(last.Metadata, `"to_seq":5`) {
		t.Fatalf("pruned event = %+v", last)
	}
	// Pruning again with nothing old is a no-op.
	if n, err := f.w.Prune(ctx, "tenant-1", now.Add(-30*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("second prune = %d %v", n, err)
	}
}

func TestExportRoundTrip(t *testing.T) {
	f := setup(t)
	f.write(t, 4)
	var buf bytes.Buffer
	if err := Export(ctx, f.st, "tenant-1", nil, nil, func(b []byte) error { buf.Write(b); return nil }); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&buf)
	prev := ZeroHash
	n := 0
	for sc.Scan() {
		var x ExportedEvent
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			t.Fatal(err)
		}
		e := FromExported(x)
		h, _ := Hash(e)
		if e.PrevHash != prev || h != e.Hash {
			t.Fatalf("exported event %d does not verify offline", e.Seq)
		}
		prev = e.Hash
		n++
	}
	if n != 4 {
		t.Fatalf("exported %d events", n)
	}
}
