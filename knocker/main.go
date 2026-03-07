// MoaV Port Knocker — HMAC-based connection admission proxy (GFK-style).
//
// Server mode (default): Listens for TCP connections. Reads first tokenLen bytes
// as a HMAC-SHA256 time-window token. Valid connections are forwarded to the
// upstream proxy (sing-box:1080). Invalid connections — including DPI probes —
// are silently forwarded to the decoy HTTP server so they receive a convincing
// response and never see VLESS/Trojan traffic.
//
// Client mode (-client): Acts as a local transparent TCP proxy. For every
// inbound connection it computes the current token from the shared secret,
// connects to the remote knocker, prepends the token, then pipes both sides.
// The client side of sing-box (or any app) connects to this local port as if
// it were a direct SOCKS5 proxy.
//
// Token rotation: HMAC-SHA256(secret, floor(unix_time / windowSecs)).
// The server accepts the current and previous window to absorb clock skew.
// Operators can read the current token from the knocker's stdout for manual
// DNS TXT record publishing, or use the built-in Cloudflare updater.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	// tokenLen is the number of bytes read/written at the start of each connection.
	tokenLen = 16
	// windowSecs is the token rotation period (5 minutes).
	windowSecs = 300
)

// computeToken returns the expected tokenLen-byte token for the given UNIX
// time window index.
func computeToken(secret string, window int64) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(window, 10)))
	return mac.Sum(nil)[:tokenLen]
}

// currentWindow returns the current 5-minute window index.
func currentWindow() int64 { return time.Now().Unix() / windowSecs }

// validateToken checks the candidate bytes against the current and previous
// rotation window (to tolerate up to windowSecs of clock skew).
func validateToken(secret string, candidate []byte) bool {
	w := currentWindow()
	for _, win := range []int64{w, w - 1} {
		if hmac.Equal(computeToken(secret, win), candidate) {
			return true
		}
	}
	return false
}

// dnsTokenB64 returns the base64url-encoded current token for DNS TXT publishing.
func dnsTokenB64(secret string) string {
	return base64.URLEncoding.EncodeToString(computeToken(secret, currentWindow()))
}

// logToken prints the current token information to log output.
func logToken(secret string) {
	t := computeToken(secret, currentWindow())
	exp := (currentWindow()+1)*windowSecs - time.Now().Unix()
	log.Printf("[knocker] Token hex  : %s", hex.EncodeToString(t))
	log.Printf("[knocker] Token b64  : %s", dnsTokenB64(secret))
	log.Printf("[knocker] Expires in : %ds", exp)
	log.Printf("[knocker] DNS TXT    : v=1 t=%s", dnsTokenB64(secret))
	// Print machine-parseable line for shell scripts that source this output
	fmt.Printf("KNOCKER_DNS_TOKEN=%s\n", dnsTokenB64(secret))
}

// pipe copies data from src to dst and signals done when finished.
func pipe(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer dst.(*net.TCPConn).CloseWrite() //nolint:errcheck
	io.Copy(dst, src)                     //nolint:errcheck
}

// proxyConn connects to dstAddr, optionally prepends bytes, then pipes
// bidirectionally between src and the newly opened dst connection.
func proxyConn(src net.Conn, dstAddr string, prepend []byte) {
	defer src.Close()
	dst, err := net.DialTimeout("tcp", dstAddr, 10*time.Second)
	if err != nil {
		log.Printf("[knocker] dial %s: %v", dstAddr, err)
		return
	}
	defer dst.Close()

	if len(prepend) > 0 {
		if _, err := dst.Write(prepend); err != nil {
			log.Printf("[knocker] upstream write prepend: %v", err)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(dst, src, &wg)
	go pipe(src, dst, &wg)
	wg.Wait()
}

// ─── Server mode ────────────────────────────────────────────────────────────

func handleServerConn(conn net.Conn, secret, upstream, decoy string) {
	header := make([]byte, tokenLen)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	if validateToken(secret, header) {
		log.Printf("[knocker] ADMIT  %s → %s", conn.RemoteAddr(), upstream)
		// Do NOT prepend — consume the token header, forward raw stream
		go proxyConn(conn, upstream, nil)
	} else {
		log.Printf("[knocker] REJECT %s → decoy %s", conn.RemoteAddr(), decoy)
		// Forward with the consumed bytes re-prepended so the decoy gets a
		// complete HTTP/TLS request and can respond convincingly.
		go proxyConn(conn, decoy, header)
	}
}

func runServer(secret, listen, upstream, decoy string) {
	logToken(secret)
	log.Printf("[knocker] Mode     : server")
	log.Printf("[knocker] Listen   : %s", listen)
	log.Printf("[knocker] Upstream : %s", upstream)
	log.Printf("[knocker] Decoy    : %s", decoy)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("[knocker] listen %s: %v", listen, err)
	}

	// Rotate token log every window
	go func() {
		for {
			remaining := (currentWindow()+1)*windowSecs - time.Now().Unix()
			time.Sleep(time.Duration(remaining+1) * time.Second)
			log.Println("[knocker] Token rotated:")
			logToken(secret)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("[knocker] Shutting down")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleServerConn(conn, secret, upstream, decoy)
	}
}

// ─── Client mode ────────────────────────────────────────────────────────────

func handleClientConn(localConn net.Conn, remoteAddr, secret string) {
	defer localConn.Close()

	remoteConn, err := net.DialTimeout("tcp", remoteAddr, 15*time.Second)
	if err != nil {
		log.Printf("[knocker-client] dial remote %s: %v", remoteAddr, err)
		return
	}
	defer remoteConn.Close()

	// Send fresh token (always compute at connection time so it's current)
	token := computeToken(secret, currentWindow())
	if _, err := remoteConn.Write(token); err != nil {
		log.Printf("[knocker-client] write token: %v", err)
		return
	}

	// Transparent bidirectional pipe: remote is now sing-box:1080 (SOCKS5)
	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(remoteConn, localConn, &wg)
	go pipe(localConn, remoteConn, &wg)
	wg.Wait()
}

func runClient(secret, listen, remoteAddr string) {
	log.Printf("[knocker-client] Mode   : client")
	log.Printf("[knocker-client] Listen : %s  (local SOCKS5 passthrough)", listen)
	log.Printf("[knocker-client] Remote : %s  (knocker server)", remoteAddr)
	log.Printf("[knocker-client] Token  : %s", hex.EncodeToString(computeToken(secret, currentWindow())))

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("[knocker-client] listen %s: %v", listen, err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("[knocker-client] Shutting down")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleClientConn(conn, remoteAddr, secret)
	}
}

// ─── Entry point ────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	clientMode := flag.Bool("client", false, "Run in client mode (token-prepend TCP proxy)")
	remoteAddr := flag.String("remote", "", "Remote knocker address for client mode (HOST:PORT)")
	flag.Parse()

	// Load secret — env var > /state/keys/knocker.secret file
	secret := os.Getenv("KNOCKER_SECRET")
	if secret == "" {
		keyFile := "/state/keys/knocker.secret"
		if data, err := os.ReadFile(keyFile); err == nil {
			secret = string(data)
			log.Printf("[knocker] Loaded secret from %s", keyFile)
		}
	}

	if secret == "" {
		if *clientMode {
			log.Fatal("[knocker-client] KNOCKER_SECRET not set — pass via env or /state/keys/knocker.secret")
		}
		// Server: auto-generate ephemeral secret and warn
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal("[knocker] generate ephemeral secret: ", err)
		}
		secret = hex.EncodeToString(b)
		log.Printf("[knocker] WARNING: KNOCKER_SECRET not set — using ephemeral secret (tokens will change on restart)")
		log.Printf("[knocker] Add to .env:  KNOCKER_SECRET=%s", secret)
	}

	if *clientMode {
		if *remoteAddr == "" {
			*remoteAddr = envOr("KNOCKER_REMOTE", "")
		}
		if *remoteAddr == "" {
			log.Fatal("[knocker-client] -remote or KNOCKER_REMOTE must be set")
		}
		listen := envOr("KNOCKER_CLIENT_LISTEN", ":1081")
		runClient(secret, listen, *remoteAddr)
	} else {
		listen := envOr("KNOCKER_LISTEN", ":8444")
		upstream := envOr("KNOCKER_UPSTREAM", "sing-box:1080")
		decoy := envOr("KNOCKER_DECOY", "decoy:80")
		runServer(secret, listen, upstream, decoy)
	}
}
