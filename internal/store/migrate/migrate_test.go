package migrate

import (
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	got := Split(`-- comment
CREATE TABLE a (
    x INTEGER -- trailing
);

CREATE INDEX b ON a(x);
`)
	if len(got) != 2 || !strings.HasPrefix(got[0], "CREATE TABLE a") || got[1] != "CREATE INDEX b ON a(x)" {
		t.Fatalf("split = %q", got)
	}
}

func TestAllOrderedAndNonEmpty(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("expected at least 2 migrations, got %d", len(all))
	}
	for i, m := range all {
		if m.Version != i+1 {
			t.Errorf("migration %d has version %d", i, m.Version)
		}
		if len(m.Statements) == 0 {
			t.Errorf("migration %d is empty", m.Version)
		}
	}
}
