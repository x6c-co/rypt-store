package ids

import (
	"sort"
	"testing"
	"time"
)

func TestCrockfordRoundTrip(t *testing.T) {
	id := New()
	enc, err := UUIDToCrockford(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 26 {
		t.Fatalf("encoded length = %d", len(enc))
	}
	back, err := CrockfordToUUID(enc)
	if err != nil || back != id {
		t.Fatalf("round trip = %s %v, want %s", back, err, id)
	}
}

func TestTimeFormatSortsLexically(t *testing.T) {
	base := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	times := []time.Time{base.Add(time.Hour), base, base.Add(10 * time.Millisecond), base.Add(999 * time.Millisecond)}
	strs := make([]string, len(times))
	for i, tm := range times {
		strs[i] = FormatTime(tm)
	}
	sort.Strings(strs)
	want := []string{"2026-10-16T09:00:00.000Z", "2026-10-16T09:00:00.010Z", "2026-10-16T09:00:00.999Z", "2026-10-16T10:00:00.000Z"}
	for i := range want {
		if strs[i] != want[i] {
			t.Fatalf("sorted = %v", strs)
		}
	}
	p, err := ParseTime(want[1])
	if err != nil || !p.Equal(base.Add(10*time.Millisecond)) {
		t.Fatalf("parse = %v %v", p, err)
	}
}

func TestUUIDv7Ordered(t *testing.T) {
	a := New()
	time.Sleep(2 * time.Millisecond)
	b := New()
	if !(a < b) || !Valid(a) {
		t.Fatalf("ids not time-ordered: %s %s", a, b)
	}
}

func TestEqualHash(t *testing.T) {
	if !EqualHash(HashToken("x"), HashToken("x")) || EqualHash(HashToken("x"), HashToken("y")) {
		t.Fatal("EqualHash")
	}
}
