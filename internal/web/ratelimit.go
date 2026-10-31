package web

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// loginLimiter bremst Passwort-Raten: nach loginFreeTries Fehlversuchen für dasselbe Paar
// aus Client-IP und Benutzername wächst die Sperrzeit exponentiell (2 s, 4 s, … bis 15 min).
// Bewusst nur das Paar: Eine Sperre pro Benutzer oder pro IP ließe Fremde den Admin bzw.
// hinter einem Reverse Proxy alle aussperren. Die echte Client-IP kommt hinter einem Proxy
// aus X-Forwarded-For, aber nur wenn der Proxy in TRUSTED_PROXIES steht.
const (
	loginFreeTries = 5
	loginMaxDelay  = 15 * time.Minute
	loginForget    = time.Hour
	loginMaxKeys   = 10000
)

type loginState struct {
	fails int
	until time.Time
	last  time.Time
}

var (
	loginMu    sync.Mutex
	loginFails = map[string]*loginState{}
)

// trustedProxies: kommagetrennte IPs oder Netze, z. B. "172.18.0.0/16,10.0.0.5".
var trustedProxies = func() []*net.IPNet {
	var out []*net.IPNet
	for _, p := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ":") {
				p += "/128"
			} else {
				p += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			out = append(out, n)
		} else {
			log.Printf("TRUSTED_PROXIES: %q ignoriert: %v", p, err)
		}
	}
	return out
}()

func trusted(ip net.IP) bool {
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP: RemoteAddr, oder hinter einem vertrauenswürdigen Proxy der letzte nicht
// vertrauenswürdige Eintrag aus X-Forwarded-For.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !trusted(ip) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := net.ParseIP(strings.TrimSpace(hops[i]))
		if h == nil {
			break
		}
		if !trusted(h) {
			return h.String()
		}
	}
	return host
}

func loginKeys(r *http.Request, username string) []string {
	return []string{clientIP(r) + "|" + strings.ToLower(username)}
}

// loginBlocked meldet, wie lange noch gesperrt ist (0 = nicht gesperrt).
func loginBlocked(keys []string) time.Duration {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		if st := loginFails[k]; st != nil && st.until.After(now) {
			if d := st.until.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait
}

func loginFailed(keys []string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	for k, st := range loginFails {
		if now.Sub(st.last) > loginForget {
			delete(loginFails, k)
		}
	}
	if len(loginFails) >= loginMaxKeys {
		loginFails = map[string]*loginState{} // Notbremse gegen Speicherverbrauch
	}
	for _, k := range keys {
		st := loginFails[k]
		if st == nil {
			st = &loginState{}
			loginFails[k] = st
		}
		st.fails++
		st.last = now
		if over := st.fails - loginFreeTries; over > 0 {
			d := time.Second << min(over, 10)
			st.until = now.Add(min(d, loginMaxDelay))
		}
	}
}

func loginSucceeded(keys []string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	for _, k := range keys {
		delete(loginFails, k)
	}
}
