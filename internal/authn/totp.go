package authn

import (
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP settings (core 7.2): RFC 6238, 30-second step, SHA-1, 6 digits.
const totpPeriod = 30

var codeOpts = totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// NewTOTPSecret generates a secret and its otpauth:// URL for an account.
func NewTOTPSecret(issuer, account string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account, Period: totpPeriod,
		Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1, SecretSize: 20})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// TOTPVerifier validates codes within one step of skew and refuses a time
// step once it has been accepted for a user, so that an observed code
// cannot be replayed.
type TOTPVerifier struct {
	mu   sync.Mutex
	used map[string]int64 // user ID -> last accepted time step
	now  func() time.Time
}

func NewTOTPVerifier(now func() time.Time) *TOTPVerifier {
	if now == nil {
		now = time.Now
	}
	return &TOTPVerifier{used: map[string]int64{}, now: now}
}

// Verify checks code against secret for userID.
func (v *TOTPVerifier) Verify(userID, secret, code string) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return false
	}
	now := v.now()
	for _, delta := range []int64{0, -1, 1} {
		at := now.Add(time.Duration(delta*totpPeriod) * time.Second)
		want, err := totp.GenerateCodeCustom(secret, at, codeOpts)
		if err != nil {
			return false
		}
		if !EqualConstantTime(want, code) {
			continue
		}
		step := at.Unix() / totpPeriod
		v.mu.Lock()
		defer v.mu.Unlock()
		if last, ok := v.used[userID]; ok && step <= last {
			return false
		}
		v.used[userID] = step
		return true
	}
	return false
}
