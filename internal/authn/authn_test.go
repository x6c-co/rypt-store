package authn

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/x6c-co/rypt-store/internal/ids"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("phc = %s", h)
	}
	if !VerifyPassword("correct horse battery", h) || VerifyPassword("wrong horse battery", h) {
		t.Fatal("verify")
	}
	if VerifyPassword("anything", "") || VerifyPassword("x", "$argon2id$garbage") {
		t.Fatal("empty or malformed hash verified")
	}
}

func TestValidatePassword(t *testing.T) {
	if ValidatePassword("short") == nil || ValidatePassword(strings.Repeat("a", 1025)) == nil {
		t.Fatal("length limits not enforced")
	}
	// No composition rules; length counts characters, not bytes.
	if err := ValidatePassword("aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePassword("ééééééééééé"); err == nil {
		t.Fatal("11 characters accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := NewRecoveryCodes(10)
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 17 || seen[c] {
			t.Fatalf("bad or duplicate code %q", c)
		}
		seen[c] = true
	}
	h, err := HashRecoveryCode(codes[0])
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := VerifyHash(NormalizeRecoveryCode(strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))), h)
	if !ok {
		t.Fatal("normalized code did not verify")
	}
}

func TestServiceTokenFormat(t *testing.T) {
	id := ids.New()
	tok, full, err := NewServiceToken(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(full, "rst_") {
		t.Fatalf("token = %s", full)
	}
	parsed, err := ParseServiceToken(full)
	if err != nil || parsed.ID != id || parsed.Secret != tok.Secret || len(parsed.Prefix()) != 8 {
		t.Fatalf("parse = %+v %v", parsed, err)
	}
	for _, bad := range []string{"rst_", "rst_abc_def", "rsc_" + full[4:], full[:30]} {
		if _, err := ParseServiceToken(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestTOTPReplay(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	v := NewTOTPVerifier(func() time.Time { return now })
	secret, url, err := NewTOTPSecret("rypt-store", "a@example.com")
	if err != nil || !strings.HasPrefix(url, "otpauth://totp/") {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(secret, now)
	if !v.Verify("u1", secret, code) {
		t.Fatal("valid code refused")
	}
	if v.Verify("u1", secret, code) {
		t.Fatal("replayed code accepted")
	}
	prev, _ := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if v.Verify("u1", secret, prev) {
		t.Fatal("older step accepted after a newer one")
	}
	if !v.Verify("u2", secret, code) {
		t.Fatal("replay protection is per user")
	}
	if v.Verify("u3", secret, "000000") && code != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestFailureLimiter(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	l := NewLoginLimiter(func() time.Time { return now })
	for range 9 {
		l.Fail("a@example.com", "1.1.1.1")
	}
	if l.Blocked("a@example.com", "2.2.2.2") {
		t.Fatal("blocked after 9 failures")
	}
	l.Fail("a@example.com", "1.1.1.1")
	if !l.Blocked("a@example.com", "2.2.2.2") {
		t.Fatal("not blocked after 10 account failures")
	}
	now = now.Add(15 * time.Minute)
	if l.Blocked("a@example.com", "2.2.2.2") {
		t.Fatal("still blocked after the window")
	}
	for i := range 30 {
		l.Fail(strings.Repeat("x", i+1), "3.3.3.3")
	}
	if !l.Blocked("someone-else", "3.3.3.3") {
		t.Fatal("IP not blocked after 30 failures")
	}
}
