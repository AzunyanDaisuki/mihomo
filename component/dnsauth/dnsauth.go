package dnsauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// These values can be injected with:
// -X github.com/metacubex/mihomo/component/dnsauth.GlobalDNSAuthSecret=...
// -X github.com/metacubex/mihomo/component/dnsauth.GlobalDNSAuthDomains=...
var GlobalDNSAuthSecret string
var GlobalDNSAuthDomains string

const (
	dnsAuthWindowSeconds = 300
	dnsAuthTokenBytes    = 10
)

var dnsAuthEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type settings struct {
	secret   string
	window   int64
	suffixes []string
}

var (
	stateLock   sync.RWMutex
	current     *settings
	maskEnabled bool
	replacer    *strings.Replacer
)

func configuredSecret() string {
	if s := strings.TrimSpace(GlobalDNSAuthSecret); s != "" {
		return s
	}
	return strings.TrimSpace(os.Getenv("DNS_AUTH_SECRET"))
}

func configuredDomains() string {
	if s := strings.TrimSpace(GlobalDNSAuthDomains); s != "" {
		return s
	}
	return strings.TrimSpace(os.Getenv("DNS_AUTH_DOMAINS"))
}

func suffixesFromConfig() []string {
	domains := configuredDomains()
	if domains == "" {
		return nil
	}

	seen := make(map[string]struct{})
	suffixes := make([]string, 0)
	for _, d := range strings.Split(domains, ",") {
		s := strings.ToLower(strings.TrimSpace(d))
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimSuffix(s, ".")
		if s == "" || strings.Contains(s, "*") {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		suffixes = append(suffixes, s)
	}
	return suffixes
}

func (s *settings) matchSuffix(name string) bool {
	for _, suf := range s.suffixes {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return true
		}
	}
	return false
}

func normalizeProxyHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return strings.ToLower(strings.Trim(strings.TrimSuffix(host, "."), "[]"))
}

func proxyHost(proxy C.Proxy) string {
	if proxy == nil {
		return ""
	}
	return normalizeProxyHost(proxy.Addr())
}

func hasManagedProxy(s *settings, proxies map[string]C.Proxy) bool {
	for _, proxy := range proxies {
		host := proxyHost(proxy)
		if host != "" && s.matchSuffix(host) {
			return true
		}
	}
	return false
}

func setCurrent(s *settings) {
	stateLock.Lock()
	current = s
	stateLock.Unlock()
}

func currentSettings() *settings {
	stateLock.RLock()
	defer stateLock.RUnlock()
	return current
}

// ApplyForProxies enables DNS auth only when the active config actually
// contains a proxy whose server host matches DNS_AUTH_DOMAINS.
func ApplyForProxies(proxies map[string]C.Proxy) bool {
	suffixes := suffixesFromConfig()
	if len(suffixes) == 0 {
		setCurrent(nil)
		setMaskedAddrs(false, nil)
		return false
	}

	s := &settings{
		secret:   configuredSecret(),
		window:   dnsAuthWindowSeconds,
		suffixes: suffixes,
	}
	if !hasManagedProxy(s, proxies) {
		setCurrent(nil)
		setMaskedAddrs(false, nil)
		return false
	}
	if s.secret == "" {
		setCurrent(nil)
		setMaskedAddrs(false, nil)
		log.Warnln("[DNS-Auth] managed proxy suffix matched but DNS_AUTH_SECRET is not configured")
		return false
	}

	setCurrent(s)
	setMaskedAddrs(true, proxies)
	installResolver()
	log.Infoln("[DNS-Auth] enabled for %d managed suffix(es)", len(suffixes))
	return true
}

func computeToken(secret, basename string, window int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(basename))
	mac.Write([]byte{'|'})
	mac.Write([]byte(strconv.FormatInt(window, 10)))
	sum := mac.Sum(nil)
	return strings.ToLower(dnsAuthEncoding.EncodeToString(sum[:dnsAuthTokenBytes]))
}

func tokenizeHost(host string) string {
	s := currentSettings()
	if s == nil || host == "" {
		return host
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if !s.matchSuffix(name) {
		return host
	}
	window := time.Now().Unix() / s.window
	return computeToken(s.secret, name, window) + "." + name
}

type tokenInjectResolver struct {
	resolver.Resolver
}

func (t *tokenInjectResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return t.Resolver.LookupIP(ctx, tokenizeHost(host))
}

func (t *tokenInjectResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return t.Resolver.LookupIPv4(ctx, tokenizeHost(host))
}

func (t *tokenInjectResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return t.Resolver.LookupIPv6(ctx, tokenizeHost(host))
}

func (t *tokenInjectResolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return t.Resolver.ResolveECH(ctx, tokenizeHost(host))
}

func installResolver() {
	if currentSettings() == nil {
		return
	}
	inner := resolver.ProxyServerHostResolver
	if inner == nil {
		return
	}
	if _, ok := inner.(*tokenInjectResolver); ok {
		return
	}
	resolver.ProxyServerHostResolver = &tokenInjectResolver{Resolver: inner}
}

func setMaskedAddrs(enabled bool, proxies map[string]C.Proxy) {
	stateLock.Lock()
	defer stateLock.Unlock()

	maskEnabled = enabled
	replacer = nil
	if !enabled {
		return
	}

	seen := make(map[string]bool)
	var replacerArgs []string
	for _, proxy := range proxies {
		host := proxyHost(proxy)
		if host == "" || host == "127.0.0.1" || host == "localhost" || host == "0.0.0.0" || host == "::1" {
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		replacerArgs = append(replacerArgs, host, "***")
	}
	if len(replacerArgs) > 0 {
		replacer = strings.NewReplacer(replacerArgs...)
	}
}

func MaskLogPayload(payload string) string {
	stateLock.RLock()
	defer stateLock.RUnlock()
	if !maskEnabled || replacer == nil {
		return payload
	}
	return replacer.Replace(payload)
}
