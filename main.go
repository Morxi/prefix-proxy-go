package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Example host: http-10-0-0-123-3000.example.com
// We map to:    http://172.21.170.252:3000
// Or          https-10-0-0-123-3000.example.com -> https://172.21.170.252:3000
var (
	// Matches: <scheme>-<ip-dashed>-<port>[.<rest>]
	// Captures:
	//  1: scheme (http|https)
	//  2: ip dashed (e.g., 10-0-0-123)
	//  3: port (digits)
	// Note: accept a user-provided variant "htttps" and normalize to "https".
	hostPattern = regexp.MustCompile(`^(https?|htttps)-((?:[0-9]{1,3}-){3}[0-9]{1,3})-([0-9]{1,5})(?:\..+)?$`)
)

func main() {
	addr := getenv("LISTEN_ADDR", ":5670")
	askAddr := getenv("ASK_LISTEN_ADDR", ":5671")
	readTimeout := durationEnv("READ_TIMEOUT", 15*time.Second)
	writeTimeout := durationEnv("WRITE_TIMEOUT", 30*time.Second)
	idleTimeout := durationEnv("IDLE_TIMEOUT", 60*time.Second)

	proxy := &httputil.ReverseProxy{Director: director, Transport: proxyTransport(), ErrorHandler: proxyErrorHandler}

	h := withCommonHeaders(proxy)

	srv := &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Start ask server for Caddy on_demand TLS validation
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ask", askAllowHandler)
		askSrv := &http.Server{
			Addr:         askAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  30 * time.Second,
		}
		log.Printf("ask endpoint listening on %s", askAddr)
		if err := askSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("ask server error: %v", err)
		}
	}()

	log.Printf("prefix-proxy listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

// director rewrites the incoming request to target parsed from Host header.
func director(req *http.Request) {
	// Keep original host for X-Forwarded-Host
	originalHost := req.Host

	scheme, ip, port, ok := parseHost(originalHost)
	if !ok {
		// No match; return 502 via ErrorHandler by hitting an invalid scheme/URL
		req.URL = &url.URL{Scheme: "http", Host: "invalid.invalid"}
		return
	}

	// Build target URL
	targetHostPort := net.JoinHostPort(ip, port)
	req.URL.Scheme = scheme
	req.URL.Host = targetHostPort

	// Ensure RequestURI is empty as required by http.Client
	req.RequestURI = ""

	// Set Host header to upstream host:port to satisfy many backends
	req.Host = targetHostPort

	// Standard forward headers
	clientIP := clientIPFromRequest(req)
	appendHeader(req.Header, "X-Forwarded-For", clientIP)
	req.Header.Set("X-Forwarded-Host", originalHost)
	req.Header.Set("X-Forwarded-Proto", forwardedProto(req))
	req.Header.Set("X-Real-IP", clientIP)

	// Remove Hop-by-hop headers per RFC 7230 6.1, but preserve Upgrade headers for WebSocket
	removeHopByHopHeaders(req)
}

func proxyTransport() http.RoundTripper {
	// Customize timeouts and keep-alives
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 60 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       upstreamTLSConfig(),
	}
	return transport
}

func upstreamTLSConfig() *tls.Config {
	// Control certificate verification via env: UPSTREAM_TLS_INSECURE_SKIP_VERIFY=true|false
	insecure := getEnvBool("UPSTREAM_TLS_INSECURE_SKIP_VERIFY", true)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure,
	}
}

func proxyErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	log.Printf("proxy error for %s %s host=%s: %v", req.Method, req.URL.String(), req.Host, err)
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusBadGateway)
	_, _ = rw.Write([]byte("Bad Gateway"))
}

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Basic health endpoint
		if req.URL.Path == "/healthz" {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("ok"))
			return
		}

		// Validate host format early
		if !hostPattern.MatchString(req.Host) {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = rw.Write([]byte("invalid host format; expected: http-<ip-dashed>-<port> or https-<ip-dashed>-<port>\nexample: http-10-0-0-123-3000"))
			return
		}

		// Set proxy headers on response
		rw.Header().Set("Server", "prefix-proxy-go")
		rw.Header().Set("Via", "1.1 prefix-proxy-go")

		next.ServeHTTP(rw, req)
	})
}

// askAllowHandler handles Caddy's on-demand TLS ask check.
// It allows issuance only when the requested domain matches our supported pattern:
//
//	^(http|https|htttps)-<ip-dashed>-<port>(\..+)?$
func askAllowHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	if req.Method != http.MethodGet {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		log.Printf("ask deny method remote=%s method=%s ua=%q dur=%s", req.RemoteAddr, req.Method, req.UserAgent(), time.Since(start))
		return
	}
	domain := req.URL.Query().Get("domain")
	if domain == "" {
		rw.WriteHeader(http.StatusBadRequest)
		log.Printf("ask bad request: missing domain remote=%s ua=%q dur=%s", req.RemoteAddr, req.UserAgent(), time.Since(start))
		_, _ = rw.Write([]byte("missing domain"))
		return
	}

	allowed := hostPattern.MatchString(domain)
	var scheme, ipDashed, ip, port string
	if allowed {
		m := hostPattern.FindStringSubmatch(domain)
		if len(m) == 4 {
			scheme = m[1]
			if scheme == "htttps" {
				scheme = "https"
			}
			ipDashed = m[2]
			ip = strings.ReplaceAll(ipDashed, "-", ".")
			port = m[3]
		}
	}

	if allowed {
		log.Printf("ask allow remote=%s domain=%s scheme=%s ip=%s port=%s ua=%q dur=%s", req.RemoteAddr, domain, scheme, ip, port, req.UserAgent(), time.Since(start))
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok"))
		return
	}
	log.Printf("ask deny remote=%s domain=%s ua=%q dur=%s", req.RemoteAddr, domain, req.UserAgent(), time.Since(start))
	rw.WriteHeader(http.StatusForbidden)
	_, _ = rw.Write([]byte("forbidden"))
}

func parseHost(host string) (scheme string, ip string, port string, ok bool) {
	m := hostPattern.FindStringSubmatch(host)
	if len(m) != 4 {
		return "", "", "", false
	}
	dashedIP := m[2]
	dottedIP := strings.ReplaceAll(dashedIP, "-", ".")
	scheme = m[1]
	if scheme == "htttps" { // normalize typo to https
		scheme = "https"
	}
	return scheme, dottedIP, m[3], true
}

func removeHopByHopHeaders(req *http.Request) {
	headers := req.Header

	// Detect WebSocket upgrade to avoid stripping critical headers
	connectionHeader := strings.ToLower(headers.Get("Connection"))
	upgradeHeader := strings.ToLower(headers.Get("Upgrade"))
	isUpgrade := strings.Contains(connectionHeader, "upgrade") || upgradeHeader != ""

	// Standard hop-by-hop headers list
	hopByHop := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		// Note: "Upgrade" is intentionally NOT listed; see handling below
	}

	// Remove any tokens listed in Connection header, except "upgrade" when upgrading
	for _, v := range headers.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			name := strings.TrimSpace(token)
			if name == "" {
				continue
			}
			if isUpgrade && strings.EqualFold(name, "upgrade") {
				continue
			}
			headers.Del(name)
		}
	}

	// Remove standard hop-by-hop headers, but preserve Connection/Upgrade for upgrades
	for _, k := range hopByHop {
		if isUpgrade && strings.EqualFold(k, "Connection") {
			continue
		}
		headers.Del(k)
	}

	// When upgrading, ensure required headers remain present
	if isUpgrade {
		if connectionHeader == "" {
			headers.Set("Connection", "Upgrade")
		}
		if upgradeHeader == "" {
			headers.Set("Upgrade", "websocket")
		}
	}
}

func appendHeader(h http.Header, key, value string) {
	if value == "" {
		return
	}
	h.Add(key, value)
}

func forwardedProto(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	// Some proxies in front may set X-Forwarded-Proto already
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func clientIPFromRequest(req *http.Request) string {
	// If already behind another proxy, trust the leftmost X-Forwarded-For
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "t", "true", "y", "yes":
		return true
	case "0", "f", "false", "n", "no":
		return false
	default:
		return def
	}
}

// gracefulShutdown demonstrates how to shut down the server with context.
// Currently not wired, but kept for potential future use.
func gracefulShutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
