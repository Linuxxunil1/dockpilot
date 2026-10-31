package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dockpilot/internal/config"
	"dockpilot/internal/users"
)

// RandomToken returns a 32-byte hex random string suitable for agent tokens.
func RandomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// MakeToken creates a signed, time-stamped session token for the given user:
// base64url(username).timestamp.sessionNonce.hmac
// Die Nonce macht Abmelden und Passwortwechsel serverseitig wirksam.
func MakeToken(u users.User) string {
	creds, _ := config.LoadCreds()
	name := base64.RawURLEncoding.EncodeToString([]byte(u.Username))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	return fmt.Sprintf("%s.%s.%s.%s", name, ts, u.SessionNonce, sign(creds.Secret, name, ts, u.SessionNonce))
}

func sign(secret string, parts ...string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.Join(parts, ".")))
	return hex.EncodeToString(mac.Sum(nil))
}

// tokenUser validates a session token and returns the username and session nonce it was issued for.
func tokenUser(token string) (string, string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", false
	}
	u, ts, nonce, sig := parts[0], parts[1], parts[2], parts[3]
	creds, _ := config.LoadCreds()
	if !hmac.Equal([]byte(sig), []byte(sign(creds.Secret, u, ts, nonce))) {
		return "", "", false
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Now().Unix()-t >= int64(config.SessionTTL) {
		return "", "", false
	}
	name, err := base64.RawURLEncoding.DecodeString(u)
	if err != nil {
		return "", "", false
	}
	return string(name), nonce, true
}

// SessionUser returns the logged-in user of the request's session cookie,
// or nil if there is no valid session or the user no longer exists.
// Im Agent-Modus gibt es keine Anmeldung, dort zählt nur der Bearer-Token des Hubs.
func SessionUser(r *http.Request) *users.User {
	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		return nil
	}
	if config.LoadMode().Mode == "agent" {
		return nil
	}
	name, nonce, ok := tokenUser(cookie.Value)
	if !ok {
		return nil
	}
	u := users.Get(name)
	if u == nil || !hmac.Equal([]byte(u.SessionNonce), []byte(nonce)) {
		return nil
	}
	return u
}

// ValidBearer prüft den Agent-Token. Er gilt nur auf einem Agent (Hub → Agent).
func ValidBearer(r *http.Request) bool {
	authHdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHdr, "Bearer ") {
		return false
	}
	token := authHdr[7:]
	m := config.LoadMode()
	if m.Mode != "agent" || m.AgentToken == "" {
		return false
	}
	return hmac.Equal([]byte(token), []byte(m.AgentToken))
}

func IsAuthenticated(r *http.Request) bool {
	return SessionUser(r) != nil || ValidBearer(r)
}

// IsCookieAuth returns true only for session-cookie auth (not bearer).
func IsCookieAuth(r *http.Request) bool {
	return SessionUser(r) != nil
}

func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   config.SessionTTL,
		HttpOnly: true,
		Secure:   config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
