package secrets

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The fixture covers feature 01 8: quotes, escapes, multi-line, export
// prefix, comments, invalid names.
const fixture = `# leading comment
PLAIN=hello world
SPACED =  padded value
export EXPORTED=yes
	export INDENTED=ok
INLINE_COMMENT=value # trailing comment
HASH_IN_VALUE=a#b
DOUBLE="double quoted # not a comment"
SINGLE='single $NOT_EXPANDED \n kept'
ESCAPES="line1\nline2\ttab \"quoted\" back\\slash \$dollar"
MULTI="first line
second line
third line"
MULTI_SINGLE='a
b'
QUOTED_THEN_COMMENT="v" # comment
EMPTY=
EMPTY_QUOTED=""
URL=postgres://u:p@host:5432/db?sslmode=require
1BAD=nope
BAD-NAME=nope
no equals sign here
UNTERMINATED_AFTER="ok" trailing
deleted=not reserved
DUP=first
DUP=second
`

func TestParseDotenvFixture(t *testing.T) {
	entries, rejected := ParseDotenv(fixture)
	got := map[string]string{}
	lines := map[string]int{}
	for _, e := range entries {
		got[e.Name] = e.Value
		lines[e.Name] = e.Line
	}
	want := map[string]string{
		"PLAIN": "hello world", "SPACED": "padded value", "EXPORTED": "yes", "INDENTED": "ok",
		"INLINE_COMMENT": "value", "HASH_IN_VALUE": "a#b", "DOUBLE": "double quoted # not a comment",
		"SINGLE": `single $NOT_EXPANDED \n kept`, "ESCAPES": "line1\nline2\ttab \"quoted\" back\\slash $dollar",
		"MULTI": "first line\nsecond line\nthird line", "MULTI_SINGLE": "a\nb", "QUOTED_THEN_COMMENT": "v",
		"EMPTY": "", "EMPTY_QUOTED": "", "URL": "postgres://u:p@host:5432/db?sslmode=require", "DUP": "second",
		"deleted": "not reserved",
	}
	if !reflect.DeepEqual(got, want) {
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q", k, got[k], v)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("unexpected %s", k)
			}
		}
	}
	if lines["MULTI_SINGLE"] != 14 || lines["QUOTED_THEN_COMMENT"] != 16 {
		t.Errorf("line numbers after multi-line values: %v", lines)
	}
	var reasons []string
	for _, r := range rejected {
		reasons = append(reasons, r.Name+"@"+strconv.Itoa(r.Line))
	}
	wantRejected := []string{"1BAD@20", "BAD-NAME@21", "@22", "UNTERMINATED_AFTER@23"}
	if strings.Join(reasons, " ") != strings.Join(wantRejected, " ") {
		t.Errorf("rejected = %v, want %v", reasons, wantRejected)
	}
}

func TestParseDotenvUnterminated(t *testing.T) {
	entries, rejected := ParseDotenv("A=1\nB=\"never closed\nC=3\n")
	if len(entries) != 1 || entries[0].Name != "A" || len(rejected) != 1 || rejected[0].Name != "B" {
		t.Fatalf("entries = %v rejected = %v", entries, rejected)
	}
}

func TestDotenvRoundTrip(t *testing.T) {
	values := map[string]string{
		"A": "plain", "B": "multi\nline\r\nvalue", "C": `quotes " and \ backslash`, "D": "$HOME and `cmd`", "E": "",
		"F": "trailing space ", "G": "# not a comment",
	}
	entries, rejected := ParseDotenv(FormatDotenv(values))
	if len(rejected) != 0 {
		t.Fatalf("rejected = %v", rejected)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	if !reflect.DeepEqual(got, values) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestFormatShell(t *testing.T) {
	if got := FormatShell(map[string]string{"A": "it's"}); got != "export A='it'\\''s'\n" {
		t.Fatalf("shell = %q", got)
	}
}

func TestValidate(t *testing.T) {
	for _, n := range []string{"A", "_x", "DATABASE_URL", "a1", strings.Repeat("A", 256), "values", "export"} {
		if ValidateName(n) != nil {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", "1A", "A-B", "A B", strings.Repeat("A", 257), "0190a3c2-0000-7000-8000-000000000000"} {
		if ValidateName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if ValidateValue(strings.Repeat("x", MaxValueBytes)) != nil || ValidateValue(strings.Repeat("x", MaxValueBytes+1)) == nil {
		t.Error("value size limit")
	}
	if ValidateValue("\xff") == nil {
		t.Error("invalid UTF-8 accepted")
	}
	if v, ok := ParseETag(`"12"`); !ok || v != 12 {
		t.Error("etag")
	}
	if v, ok := ParseETag(`W/"3"`); !ok || v != 3 {
		t.Error("weak etag")
	}
	if _, ok := ParseETag(`"x"`); ok {
		t.Error("bad etag accepted")
	}
}
