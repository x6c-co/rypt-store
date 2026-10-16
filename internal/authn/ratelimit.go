package authn

import (
	"sync"
	"time"
)

// Login rate limits (core 7.2): 10 failed attempts per account and 30 per
// source IP in any 15-minute window.
const (
	AccountFailLimit = 10
	IPFailLimit      = 30
	FailWindow       = 15 * time.Minute
)

// FailureLimiter counts recent failures per key in a sliding window.
type FailureLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	fails  map[string][]time.Time
}

func NewFailureLimiter(limit int, window time.Duration, now func() time.Time) *FailureLimiter {
	if now == nil {
		now = time.Now
	}
	return &FailureLimiter{limit: limit, window: window, now: now, fails: map[string][]time.Time{}}
}

func (l *FailureLimiter) prune(key string, now time.Time) []time.Time {
	ts := l.fails[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = ts
	}
	return ts
}

// Blocked reports whether key has reached the limit.
func (l *FailureLimiter) Blocked(key string) bool {
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, l.now())) >= l.limit
}

// Fail records a failure.
func (l *FailureLimiter) Fail(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.fails[key] = append(l.prune(key, now), now)
	// Bound memory under a flood of distinct keys.
	if len(l.fails) > 100000 {
		for k := range l.fails {
			l.prune(k, now)
		}
	}
}

// LoginLimiter combines the per-account and per-IP limits.
type LoginLimiter struct {
	Account *FailureLimiter
	IP      *FailureLimiter
}

func NewLoginLimiter(now func() time.Time) *LoginLimiter {
	return &LoginLimiter{
		Account: NewFailureLimiter(AccountFailLimit, FailWindow, now),
		IP:      NewFailureLimiter(IPFailLimit, FailWindow, now),
	}
}

// Blocked reports whether either limit is reached.
func (l *LoginLimiter) Blocked(account, ip string) bool {
	return l.Account.Blocked(account) || l.IP.Blocked(ip)
}

// Fail records a failure against both keys.
func (l *LoginLimiter) Fail(account, ip string) {
	l.Account.Fail(account)
	l.IP.Fail(ip)
}
