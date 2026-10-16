package authn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/x6c-co/rypt-store/internal/store"
)

// ceremonyTTL bounds how long a WebAuthn challenge stays valid.
const ceremonyTTL = 5 * time.Minute

// WebAuthn runs passkey registration and login ceremonies (core 7.2). The
// relying party ID is the host of server.public_url, or of the request
// when public_url is not set.
type WebAuthn struct {
	publicURL *url.URL
	now       func() time.Time

	mu         sync.Mutex
	ceremonies map[string]ceremony
}

type ceremony struct {
	data    webauthn.SessionData
	expires time.Time
}

func NewWebAuthn(publicURL string, now func() time.Time) (*WebAuthn, error) {
	w := &WebAuthn{now: now, ceremonies: map[string]ceremony{}}
	if w.now == nil {
		w.now = time.Now
	}
	if publicURL != "" {
		u, err := url.Parse(publicURL)
		if err != nil {
			return nil, err
		}
		w.publicURL = u
	}
	return w, nil
}

// Origin is the request origin and host the ceremony runs for.
type Origin struct {
	Origin string // the Origin header
	Host   string // the Host header
}

func (w *WebAuthn) instance(o Origin) (*webauthn.WebAuthn, error) {
	var rpID string
	var origins []string
	if w.publicURL != nil {
		rpID = w.publicURL.Hostname()
		origins = append(origins, w.publicURL.Scheme+"://"+w.publicURL.Host)
	} else {
		host := o.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		rpID = host
	}
	// Accept the request's own origin when it is on the RP host (another
	// port, for example the published port of a container).
	if o.Origin != "" {
		if u, err := url.Parse(o.Origin); err == nil && u.Hostname() == rpID && u.Scheme == "https" {
			origins = append(origins, o.Origin)
		}
	}
	if rpID == "" || len(origins) == 0 {
		return nil, errors.New("passkeys need an https origin on the server's host")
	}
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "rypt-store", RPOrigins: origins})
}

type waUser struct {
	u     *store.User
	creds []webauthn.Credential
}

func (x waUser) WebAuthnID() []byte                         { return []byte(x.u.ID) }
func (x waUser) WebAuthnName() string                       { return x.u.Email }
func (x waUser) WebAuthnDisplayName() string                { return x.u.DisplayName }
func (x waUser) WebAuthnCredentials() []webauthn.Credential { return x.creds }

// Credentials decodes stored credentials.
func Credentials(stored []store.WebAuthnCredential) ([]webauthn.Credential, error) {
	out := make([]webauthn.Credential, 0, len(stored))
	for _, s := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(s.Data), &c); err != nil {
			return nil, fmt.Errorf("decode passkey %s: %w", s.ID, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func (w *WebAuthn) put(key string, d *webauthn.SessionData) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	for k, c := range w.ceremonies {
		if now.After(c.expires) {
			delete(w.ceremonies, k)
		}
	}
	w.ceremonies[key] = ceremony{data: *d, expires: now.Add(ceremonyTTL)}
}

func (w *WebAuthn) take(key string) (webauthn.SessionData, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	c, ok := w.ceremonies[key]
	delete(w.ceremonies, key)
	if !ok || w.now().After(c.expires) {
		return webauthn.SessionData{}, errors.New("no passkey challenge in progress; start again")
	}
	return c.data, nil
}

// BeginRegistration returns creation options for a new passkey. key ties
// the ceremony to the caller's session.
func (w *WebAuthn) BeginRegistration(o Origin, key string, u *store.User, existing []store.WebAuthnCredential) (any, error) {
	wa, err := w.instance(o)
	if err != nil {
		return nil, err
	}
	creds, err := Credentials(existing)
	if err != nil {
		return nil, err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := wa.BeginRegistration(waUser{u: u, creds: creds},
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		return nil, err
	}
	w.put("reg:"+key, data)
	return opts, nil
}

// FinishRegistration verifies the authenticator's response and returns the
// credential to store.
func (w *WebAuthn) FinishRegistration(o Origin, key string, u *store.User, existing []store.WebAuthnCredential, response []byte) (*webauthn.Credential, error) {
	data, err := w.take("reg:" + key)
	if err != nil {
		return nil, err
	}
	wa, err := w.instance(o)
	if err != nil {
		return nil, err
	}
	creds, err := Credentials(existing)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("passkey response: %w", err)
	}
	return wa.CreateCredential(waUser{u: u, creds: creds}, data, parsed)
}

// BeginLogin returns assertion options for the user's passkeys.
func (w *WebAuthn) BeginLogin(o Origin, key string, u *store.User, existing []store.WebAuthnCredential) (any, error) {
	wa, err := w.instance(o)
	if err != nil {
		return nil, err
	}
	creds, err := Credentials(existing)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, errors.New("no passkeys registered")
	}
	opts, data, err := wa.BeginLogin(waUser{u: u, creds: creds})
	if err != nil {
		return nil, err
	}
	w.put("login:"+key, data)
	return opts, nil
}

// FinishLogin verifies an assertion and returns the updated credential.
func (w *WebAuthn) FinishLogin(o Origin, key string, u *store.User, existing []store.WebAuthnCredential, response []byte) (*webauthn.Credential, error) {
	data, err := w.take("login:" + key)
	if err != nil {
		return nil, err
	}
	wa, err := w.instance(o)
	if err != nil {
		return nil, err
	}
	creds, err := Credentials(existing)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("passkey response: %w", err)
	}
	return wa.ValidateLogin(waUser{u: u, creds: creds}, data, parsed)
}

// StoredCredential converts a library credential for storage.
func StoredCredential(c *webauthn.Credential) (cred store.WebAuthnCredential, err error) {
	data, err := json.Marshal(c)
	if err != nil {
		return cred, err
	}
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return store.WebAuthnCredential{
		CredentialID: c.ID, PublicKey: c.PublicKey, SignCount: int64(c.Authenticator.SignCount),
		Transports: strings.Join(transports, ","), Data: string(data),
	}, nil
}
