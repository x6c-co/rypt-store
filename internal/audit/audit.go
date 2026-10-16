// Package audit writes and verifies the append-only, hash-chained audit log
// (core 8): one chain per tenant plus the instance chain.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/store"
)

// Actor kinds and results (core 8.1).
const (
	ActorUser         = "user"
	ActorServiceToken = "service_token"
	ActorSystem       = "system"

	Success = "success"
	Denied  = "denied"
	Error   = "error"
)

// ZeroHash is prev_hash for seq 1.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// MaxRetries bounds how often the writer re-reads a moved head (core 8.3).
const MaxRetries = 5

// RequestInfo is the request context recorded on every event.
type RequestInfo struct {
	IP        string
	UserAgent string
	RequestID string
}

type requestInfoKey struct{}

// WithRequestInfo attaches request context for events written under ctx.
func WithRequestInfo(ctx context.Context, ri RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, ri)
}

// RequestInfoFrom returns the request context attached to ctx.
func RequestInfoFrom(ctx context.Context) RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return ri
}

// Canonical returns the canonical JSON of v: object keys sorted, no
// insignificant whitespace, UTF-8, no HTML escaping, numbers as written.
func Canonical(v any) ([]byte, error) {
	// Round-trip through any so that structs and maps alike come out with
	// sorted keys; UseNumber keeps numbers exactly as written.
	raw, err := marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return marshal(generic)
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// CanonicalMetadata canonicalizes a metadata object; nil becomes "{}".
func CanonicalMetadata(m map[string]any) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := Canonical(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Hash computes an event's hash: hex SHA-256 of prev_hash concatenated with
// the canonical JSON of every other field except hash itself (core 8.1).
func Hash(e store.AuditEvent) (string, error) {
	meta := json.RawMessage(e.Metadata)
	if e.Metadata == "" {
		meta = json.RawMessage("{}")
	}
	fields := map[string]any{
		"id":                  e.ID,
		"chain_id":            e.ChainID,
		"seq":                 e.Seq,
		"ts":                  e.TS,
		"actor_kind":          e.ActorKind,
		"actor_id":            nullable(e.ActorID),
		"action":              e.Action,
		"target_kind":         nullable(e.TargetKind),
		"target_id":           nullable(e.TargetID),
		"project_id":          nullable(e.ProjectID),
		"environment_id":      nullable(e.EnvironmentID),
		"result":              e.Result,
		"ip":                  nullable(e.IP),
		"user_agent":          nullable(e.UserAgent),
		"request_id":          nullable(e.RequestID),
		"provider_request_id": nullable(e.ProviderRequestID),
		"metadata":            meta,
	}
	c, err := Canonical(fields)
	if err != nil {
		return "", fmt.Errorf("canonicalize event: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write(c)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Writer appends events to chains.
type Writer struct {
	st  store.AuditStore
	now func() time.Time
	m   *metrics.Metrics

	mu     sync.Mutex
	chains map[string]*sync.Mutex
}

func NewWriter(st store.AuditStore, m *metrics.Metrics, now func() time.Time) *Writer {
	if now == nil {
		now = time.Now
	}
	return &Writer{st: st, now: now, m: m, chains: map[string]*sync.Mutex{}}
}

func (w *Writer) chainLock(id string) *sync.Mutex {
	w.mu.Lock()
	defer w.mu.Unlock()
	l, ok := w.chains[id]
	if !ok {
		l = &sync.Mutex{}
		w.chains[id] = l
	}
	return l
}

// Event describes an event to write. Seq, hashes, ID and timestamp are
// filled by the writer; request context comes from ctx when not set.
type Event struct {
	ChainID           string
	ActorKind         string
	ActorID           string
	Action            string
	TargetKind        string
	TargetID          string
	ProjectID         string
	EnvironmentID     string
	Result            string
	ProviderRequestID string
	Metadata          map[string]any
}

// Record writes ev on its chain. apply performs the domain change and the
// event insert as one storage batch, given the chained event; nil apply
// writes the event alone. When the chain head moved under the writer, it
// re-reads the head and calls apply again, up to MaxRetries times. Any other
// error from apply is returned as is, so domain conflicts reach the caller.
func (w *Writer) Record(ctx context.Context, in Event, apply func(*store.AuditEvent) error) error {
	if in.ChainID == "" || in.Action == "" || in.ActorKind == "" {
		return errors.New("audit event needs a chain, an actor kind, and an action")
	}
	if in.Result == "" {
		in.Result = Success
	}
	meta, err := CanonicalMetadata(in.Metadata)
	if err != nil {
		return err
	}
	ri := RequestInfoFrom(ctx)
	ev := store.AuditEvent{
		ChainID: in.ChainID, ActorKind: in.ActorKind, ActorID: in.ActorID, Action: in.Action,
		TargetKind: in.TargetKind, TargetID: in.TargetID, ProjectID: in.ProjectID, EnvironmentID: in.EnvironmentID,
		Result: in.Result, IP: ri.IP, UserAgent: truncate(ri.UserAgent, 512), RequestID: ri.RequestID,
		ProviderRequestID: in.ProviderRequestID, Metadata: meta,
	}
	if apply == nil {
		apply = func(e *store.AuditEvent) error { return w.st.AppendAudit(ctx, e) }
	}
	l := w.chainLock(in.ChainID)
	l.Lock()
	defer l.Unlock()
	for attempt := 0; ; attempt++ {
		head, err := w.st.GetAuditHead(ctx, in.ChainID)
		if errors.Is(err, store.ErrNotFound) {
			if err := w.st.EnsureAuditChain(ctx, in.ChainID); err != nil {
				return err
			}
			head, err = w.st.GetAuditHead(ctx, in.ChainID)
		}
		if err != nil {
			return fmt.Errorf("read audit head: %w", err)
		}
		e := ev
		e.ID = ids.New()
		e.TS = ids.FormatTime(w.now())
		e.Seq = head.HeadSeq + 1
		e.PrevHash = head.HeadHash
		if e.Hash, err = Hash(e); err != nil {
			return err
		}
		err = apply(&e)
		if errors.Is(err, store.ErrAuditConflict) && attempt < MaxRetries {
			// Another process advanced the head; back off with jitter so
			// that competing writers spread out.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1)*5*time.Millisecond + time.Duration(rand.IntN(10))*time.Millisecond):
			}
			continue
		}
		if w.m != nil {
			res := "written"
			if err != nil {
				res = "failed"
			}
			w.m.AuditEvents.WithLabelValues(res).Inc()
		}
		return err
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// VerifyResult is the outcome of walking a chain.
type VerifyResult struct {
	OK bool `json:"ok"`
	// Seq and Hash are the head when OK, else the first broken event's seq
	// and the hash the walk expected.
	Seq    int64  `json:"seq"`
	Hash   string `json:"hash"`
	Reason string `json:"reason,omitempty"`
	// Checked counts the events walked.
	Checked   int64 `json:"checked"`
	AnchorSeq int64 `json:"anchor_seq"`
}

func (r VerifyResult) String() string {
	if r.OK {
		return fmt.Sprintf("OK %d %s", r.Seq, r.Hash)
	}
	return fmt.Sprintf("BROKEN at seq %d: %s", r.Seq, r.Reason)
}

// Verify walks a chain from its anchor, recomputing every hash, and reports
// the first broken link (core 8.4).
func Verify(ctx context.Context, st store.AuditStore, chainID string) (VerifyResult, error) {
	head, err := st.GetAuditHead(ctx, chainID)
	if err != nil {
		return VerifyResult{}, err
	}
	prev := head.AnchorHash
	if head.AnchorSeq == 0 {
		prev = ZeroHash
	}
	expect := head.AnchorSeq + 1
	res := VerifyResult{AnchorSeq: head.AnchorSeq}
	var broken *VerifyResult
	errStop := errors.New("stop")
	err = st.ScanAuditEvents(ctx, chainID, head.AnchorSeq, nil, nil, func(e store.AuditEvent) error {
		fail := func(reason string) error {
			broken = &VerifyResult{Seq: expect, Hash: prev, Reason: reason, Checked: res.Checked, AnchorSeq: head.AnchorSeq}
			return errStop
		}
		if e.Seq != expect {
			return fail(fmt.Sprintf("event %d is missing (next stored event is %d)", expect, e.Seq))
		}
		if e.ChainID != chainID {
			return fail("event belongs to another chain")
		}
		if e.PrevHash != prev {
			return fail("prev_hash does not match the previous event's hash")
		}
		h, err := Hash(e)
		if err != nil {
			return err
		}
		if h != e.Hash {
			return fail("event content does not match its hash")
		}
		prev = e.Hash
		expect++
		res.Checked++
		return nil
	})
	if broken != nil {
		return *broken, nil
	}
	if err != nil {
		return VerifyResult{}, err
	}
	last := expect - 1
	if last != head.HeadSeq || prev != head.HeadHash {
		return VerifyResult{Seq: last + 1, Hash: prev, Checked: res.Checked, AnchorSeq: head.AnchorSeq,
			Reason: fmt.Sprintf("chain ends at %d but the recorded head is %d", last, head.HeadSeq)}, nil
	}
	res.OK, res.Seq, res.Hash = true, head.HeadSeq, head.HeadHash
	return res, nil
}

// ExportedEvent is one JSON Lines record of an export (core 8.4).
type ExportedEvent struct {
	ID                string          `json:"id"`
	ChainID           string          `json:"chain_id"`
	Seq               int64           `json:"seq"`
	TS                string          `json:"ts"`
	ActorKind         string          `json:"actor_kind"`
	ActorID           *string         `json:"actor_id"`
	Action            string          `json:"action"`
	TargetKind        *string         `json:"target_kind"`
	TargetID          *string         `json:"target_id"`
	ProjectID         *string         `json:"project_id"`
	EnvironmentID     *string         `json:"environment_id"`
	Result            string          `json:"result"`
	IP                *string         `json:"ip"`
	UserAgent         *string         `json:"user_agent"`
	RequestID         *string         `json:"request_id"`
	ProviderRequestID *string         `json:"provider_request_id"`
	Metadata          json.RawMessage `json:"metadata"`
	PrevHash          string          `json:"prev_hash"`
	Hash              string          `json:"hash"`
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ToExported converts a stored event for export and API responses.
func ToExported(e store.AuditEvent) ExportedEvent {
	meta := json.RawMessage(e.Metadata)
	if len(meta) == 0 {
		meta = json.RawMessage("{}")
	}
	return ExportedEvent{
		ID: e.ID, ChainID: e.ChainID, Seq: e.Seq, TS: e.TS, ActorKind: e.ActorKind, ActorID: ptr(e.ActorID),
		Action: e.Action, TargetKind: ptr(e.TargetKind), TargetID: ptr(e.TargetID), ProjectID: ptr(e.ProjectID),
		EnvironmentID: ptr(e.EnvironmentID), Result: e.Result, IP: ptr(e.IP), UserAgent: ptr(e.UserAgent),
		RequestID: ptr(e.RequestID), ProviderRequestID: ptr(e.ProviderRequestID), Metadata: meta,
		PrevHash: e.PrevHash, Hash: e.Hash,
	}
}

// FromExported converts an exported record back, for offline verification.
func FromExported(x ExportedEvent) store.AuditEvent {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return store.AuditEvent{
		ID: x.ID, ChainID: x.ChainID, Seq: x.Seq, TS: x.TS, ActorKind: x.ActorKind, ActorID: deref(x.ActorID),
		Action: x.Action, TargetKind: deref(x.TargetKind), TargetID: deref(x.TargetID), ProjectID: deref(x.ProjectID),
		EnvironmentID: deref(x.EnvironmentID), Result: x.Result, IP: deref(x.IP), UserAgent: deref(x.UserAgent),
		RequestID: deref(x.RequestID), ProviderRequestID: deref(x.ProviderRequestID), Metadata: string(x.Metadata),
		PrevHash: x.PrevHash, Hash: x.Hash,
	}
}

// Export streams a chain's events in seq order as JSON Lines, optionally
// bounded by time.
func Export(ctx context.Context, st store.AuditStore, chainID string, from, to *time.Time, write func([]byte) error) error {
	return st.ScanAuditEvents(ctx, chainID, 0, from, to, func(e store.AuditEvent) error {
		b, err := marshal(ToExported(e))
		if err != nil {
			return err
		}
		return write(append(b, '\n'))
	})
}

// Prune deletes events older than before from a chain and records the last
// deleted event as the new anchor, writing an audit.pruned event (core 8.5).
// It returns how many events were deleted.
func (w *Writer) Prune(ctx context.Context, chainID string, before time.Time) (int64, error) {
	head, err := w.st.GetAuditHead(ctx, chainID)
	if err != nil {
		return 0, err
	}
	anchorSeq, err := w.st.LastAuditSeqBefore(ctx, chainID, before)
	if err != nil {
		return 0, err
	}
	if anchorSeq <= head.AnchorSeq {
		return 0, nil
	}
	anchor, err := w.st.GetAuditEventBySeq(ctx, chainID, anchorSeq)
	if err != nil {
		return 0, err
	}
	deleted := anchorSeq - head.AnchorSeq
	err = w.Record(ctx, Event{
		ChainID: chainID, ActorKind: ActorSystem, Action: "audit.pruned",
		Metadata: map[string]any{"from_seq": head.AnchorSeq + 1, "to_seq": anchorSeq, "anchor_hash": anchor.Hash, "deleted": deleted},
	}, func(e *store.AuditEvent) error {
		return w.st.PruneAudit(ctx, chainID, anchorSeq, anchor.Hash, e)
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
