// DNS Router for MoaV - Routes DNS queries to dnstt or Slipstream backends
// based on domain suffix matching. Lightweight UDP forwarder with connection pooling.
//
// Token TXT responder: if KNOCKER_SECRET is set, the router synthesises DNS TXT
// responses for queries matching the pattern  _knock.<any-of-the-tunnel-domains>
// containing the current HMAC token (base64url, 16 bytes).  This allows clients
// to auto-discover the rotating knocker token through normal DNS — the same
// infrastructure ISPs are required to support for DKIM / SPF / ACME.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxPacketSize  = 4096
	defaultTimeout = 5 * time.Second
	dnsHeaderSize  = 12
	tokenWindow    = 300 // 5-minute HMAC rotation window
	tokenLen       = 16  // bytes from HMAC-SHA256
)

// knockerToken returns the base64url-encoded 16-byte HMAC token for the given
// 5-minute window index.  Same algorithm as knocker/main.go so clients can
// validate without an extra secret exchange.
func knockerToken(secret string, window int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(window, 10)))
	raw := mac.Sum(nil)[:tokenLen]
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw)
}

// currentKnockerToken returns the token for the current window.
func currentKnockerToken(secret string) string {
	return knockerToken(secret, time.Now().Unix()/tokenWindow)
}

// buildTXTResponse synthesises a DNS TXT response packet for the given query.
// The TXT record contains the current HMAC token.
func buildTXTResponse(query []byte, txtValue string) []byte {
	if len(query) < dnsHeaderSize {
		return nil
	}
	resp := make([]byte, 0, 512)

	// Copy header, set QR=1, AA=1, RA=1, RCODE=0
	resp = append(resp, query[0], query[1]) // ID
	resp = append(resp, 0x84, 0x00)         // QR=1 AA=1 RD=0 (standard query response)
	resp = append(resp, query[4], query[5]) // QDCOUNT
	resp = append(resp, 0x00, 0x01)         // ANCOUNT=1
	resp = append(resp, 0x00, 0x00)         // NSCOUNT=0
	resp = append(resp, 0x00, 0x00)         // ARCOUNT=0

	// Copy question section verbatim
	questionEnd := findQuestionEnd(query)
	if questionEnd <= dnsHeaderSize {
		return nil
	}
	resp = append(resp, query[dnsHeaderSize:questionEnd]...)

	// Answer: pointer back to the question QNAME
	resp = append(resp, 0xC0, byte(dnsHeaderSize)) // name pointer
	resp = append(resp, 0x00, 0x10)                // TYPE=TXT
	resp = append(resp, 0x00, 0x01)                // CLASS=IN
	resp = append(resp, 0x00, 0x00, 0x01, 0x2C)    // TTL=300 (match rotation window)

	// RDLENGTH + RDATA  (TXT: one string of up to 255 bytes)
	txt := []byte(txtValue)
	if len(txt) > 255 {
		txt = txt[:255]
	}
	rdLen := uint16(1 + len(txt))
	resp = append(resp, byte(rdLen>>8), byte(rdLen))
	resp = append(resp, byte(len(txt)))
	resp = append(resp, txt...)

	return resp
}

// findQuestionEnd returns the offset just past the first DNS question entry.
func findQuestionEnd(packet []byte) int {
	offset := dnsHeaderSize
	for offset < len(packet) {
		if packet[offset] == 0 {
			offset++    // skip null terminator
			offset += 4 // QTYPE + QCLASS
			return offset
		}
		if packet[offset]&0xC0 == 0xC0 {
			offset += 2 // pointer
			offset += 4
			return offset
		}
		offset += 1 + int(packet[offset])
	}
	return offset
}

// Route maps a domain suffix to a backend address.
type Route struct {
	Domain  string
	Backend string
}

// Router is a DNS packet forwarder with domain-based routing.
type Router struct {
	listenAddr    string
	routes        []Route
	conn          *net.UDPConn
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	backends      map[string]*backendConn
	backendsMu    sync.RWMutex
	timeout       time.Duration
	knockerSecret string // if set, synthesise TXT responses for _knock.<domain>
}

type backendConn struct {
	addr    *net.UDPAddr
	conn    *net.UDPConn
	mu      sync.Mutex
	pending map[uint16]chan []byte
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	timeout time.Duration
}

func main() {
	routes, err := buildRoutes()
	if err != nil {
		log.Fatalf("[dns-router] %v", err)
	}

	if len(routes) == 0 {
		log.Fatal("[dns-router] No routes configured. Set ENABLE_DNSTT=true and/or ENABLE_SLIPSTREAM=true")
	}

	listenAddr := envOr("DNS_LISTEN", ":5353")
	knockerSecret := os.Getenv("KNOCKER_SECRET")
	if knockerSecret != "" {
		log.Printf("[dns-router] Knocker TXT responder enabled — _knock.<domain> queries will return the current HMAC token")
	}

	router := newRouter(listenAddr, routes, knockerSecret)

	if err := router.start(); err != nil {
		log.Fatalf("[dns-router] Failed to start: %v", err)
	}

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("[dns-router] Shutting down...")
	router.stop()
}

func buildRoutes() ([]Route, error) {
	var routes []Route

	enableDnstt := strings.ToLower(envOr("ENABLE_DNSTT", "true"))
	enableSlipstream := strings.ToLower(envOr("ENABLE_SLIPSTREAM", "false"))

	if enableDnstt == "true" {
		domain := os.Getenv("DNSTT_DOMAIN")
		if domain == "" {
			return nil, fmt.Errorf("DNSTT_DOMAIN required when ENABLE_DNSTT=true")
		}
		backend := envOr("DNSTT_BACKEND", "dnstt:5353")
		routes = append(routes, Route{Domain: strings.ToLower(domain), Backend: backend})
		log.Printf("[dns-router] Route: *.%s -> %s (dnstt)", domain, backend)
	}

	if enableSlipstream == "true" {
		domain := os.Getenv("SLIPSTREAM_DOMAIN")
		if domain == "" {
			return nil, fmt.Errorf("SLIPSTREAM_DOMAIN required when ENABLE_SLIPSTREAM=true")
		}
		backend := envOr("SLIPSTREAM_BACKEND", "slipstream:5354")
		routes = append(routes, Route{Domain: strings.ToLower(domain), Backend: backend})
		log.Printf("[dns-router] Route: *.%s -> %s (slipstream)", domain, backend)
	}

	return routes, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- Router ---

func newRouter(listenAddr string, routes []Route, knockerSecret string) *Router {
	return &Router{
		listenAddr:    listenAddr,
		routes:        routes,
		timeout:       defaultTimeout,
		backends:      make(map[string]*backendConn),
		knockerSecret: knockerSecret,
	}
}

func (r *Router) start() error {
	addr, err := net.ResolveUDPAddr("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	r.conn = conn
	r.ctx, r.cancel = context.WithCancel(context.Background())

	r.wg.Add(1)
	go r.serve()

	log.Printf("[dns-router] Listening on %s (%d routes)", r.listenAddr, len(r.routes))
	return nil
}

func (r *Router) stop() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.conn != nil {
		r.conn.Close()
	}
	r.backendsMu.Lock()
	for _, bc := range r.backends {
		bc.close()
	}
	r.backendsMu.Unlock()
	r.wg.Wait()
}

func (r *Router) serve() {
	defer r.wg.Done()
	buf := make([]byte, maxPacketSize)

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if r.ctx.Err() != nil {
				return
			}
			log.Printf("[dns-router] Read error: %v", err)
			continue
		}

		// Copy packet for goroutine
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go r.handleQuery(packet, clientAddr)
	}
}

func (r *Router) handleQuery(packet []byte, clientAddr *net.UDPAddr) {
	queryName, err := extractQueryName(packet)
	if err != nil {
		return
	}

	// Token TXT responder: answer _knock.<domain> with the current HMAC token.
	// This lets clients auto-discover the rotating knocker token via DNS — using
	// the same TXT record infrastructure that ISPs must support for DKIM/SPF.
	if r.knockerSecret != "" && strings.HasPrefix(queryName, "_knock.") {
		baseName := strings.TrimPrefix(queryName, "_knock.")
		for _, route := range r.routes {
			if matchDomainSuffix(baseName, route.Domain) || baseName == route.Domain {
				token := currentKnockerToken(r.knockerSecret)
				resp := buildTXTResponse(packet, token)
				if resp != nil {
					r.conn.WriteToUDP(resp, clientAddr)
					log.Printf("[dns-router] TXT token served for %s (token: %s...)", queryName, token[:8])
				}
				return
			}
		}
	}

	backend := r.findBackend(queryName)
	if backend == "" {
		return
	}

	response, err := r.forward(packet, backend)
	if err != nil {
		log.Printf("[dns-router] Forward error %s -> %s: %v", queryName, backend, err)
		return
	}

	r.conn.WriteToUDP(response, clientAddr)
}

func (r *Router) findBackend(queryName string) string {
	for _, route := range r.routes {
		if matchDomainSuffix(queryName, route.Domain) {
			return route.Backend
		}
	}
	return ""
}

// --- Backend connection pool ---

func (r *Router) getBackend(addr string) (*backendConn, error) {
	r.backendsMu.RLock()
	bc, ok := r.backends[addr]
	r.backendsMu.RUnlock()
	if ok {
		return bc, nil
	}

	r.backendsMu.Lock()
	defer r.backendsMu.Unlock()

	if bc, ok = r.backends[addr]; ok {
		return bc, nil
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(r.ctx)
	bc = &backendConn{
		addr:    udpAddr,
		conn:    conn,
		pending: make(map[uint16]chan []byte),
		ctx:     ctx,
		cancel:  cancel,
		timeout: r.timeout,
	}
	bc.wg.Add(1)
	go bc.readLoop()

	r.backends[addr] = bc
	log.Printf("[dns-router] Connected to backend %s", addr)
	return bc, nil
}

func (r *Router) forward(packet []byte, backend string) ([]byte, error) {
	bc, err := r.getBackend(backend)
	if err != nil {
		return nil, err
	}
	return bc.query(packet)
}

func (bc *backendConn) query(packet []byte) ([]byte, error) {
	if len(packet) < 2 {
		return nil, fmt.Errorf("packet too short")
	}

	txid := uint16(packet[0])<<8 | uint16(packet[1])
	ch := make(chan []byte, 1)

	bc.mu.Lock()
	if _, exists := bc.pending[txid]; exists {
		bc.mu.Unlock()
		return bc.queryDirect(packet)
	}
	bc.pending[txid] = ch
	bc.mu.Unlock()

	defer func() {
		bc.mu.Lock()
		delete(bc.pending, txid)
		bc.mu.Unlock()
	}()

	if _, err := bc.conn.Write(packet); err != nil {
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(bc.timeout):
		return nil, fmt.Errorf("timeout")
	case <-bc.ctx.Done():
		return nil, fmt.Errorf("closed")
	}
}

// queryDirect is a fallback for txid collisions.
func (bc *backendConn) queryDirect(packet []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, bc.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(bc.timeout))

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, maxPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (bc *backendConn) readLoop() {
	defer bc.wg.Done()
	buf := make([]byte, maxPacketSize)

	for {
		select {
		case <-bc.ctx.Done():
			return
		default:
		}

		bc.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := bc.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if bc.ctx.Err() != nil {
				return
			}
			continue
		}
		if n < 2 {
			continue
		}

		txid := uint16(buf[0])<<8 | uint16(buf[1])
		bc.mu.Lock()
		ch, ok := bc.pending[txid]
		if ok {
			delete(bc.pending, txid)
		}
		bc.mu.Unlock()

		if ok {
			resp := make([]byte, n)
			copy(resp, buf[:n])
			select {
			case ch <- resp:
			default:
			}
		}
	}
}

func (bc *backendConn) close() {
	bc.cancel()
	bc.conn.Close()
	bc.wg.Wait()
}

// --- DNS packet parsing ---

func extractQueryName(packet []byte) (string, error) {
	if len(packet) < dnsHeaderSize+1 {
		return "", fmt.Errorf("packet too short")
	}
	// QDCOUNT at bytes 4-5
	if int(packet[4])<<8|int(packet[5]) == 0 {
		return "", fmt.Errorf("no questions")
	}

	var labels []string
	offset := dnsHeaderSize
	visited := make(map[int]bool)
	jumped := false
	endOffset := offset

	for {
		if offset >= len(packet) {
			return "", fmt.Errorf("truncated")
		}
		if visited[offset] {
			return "", fmt.Errorf("pointer loop")
		}
		visited[offset] = true

		length := int(packet[offset])
		if length == 0 {
			if !jumped {
				endOffset = offset + 1
			}
			break
		}
		// Pointer compression
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(packet) {
				return "", fmt.Errorf("truncated pointer")
			}
			ptr := int(packet[offset]&0x3F)<<8 | int(packet[offset+1])
			if !jumped {
				endOffset = offset + 2
			}
			offset = ptr
			jumped = true
			continue
		}
		if length > 63 {
			return "", fmt.Errorf("label too long")
		}
		offset++
		if offset+length > len(packet) {
			return "", fmt.Errorf("truncated label")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
	_ = endOffset

	return strings.ToLower(strings.Join(labels, ".")), nil
}

func matchDomainSuffix(queryName, suffix string) bool {
	queryName = strings.ToLower(queryName)
	suffix = strings.ToLower(suffix)
	if queryName == suffix {
		return true
	}
	return strings.HasSuffix(queryName, "."+suffix)
}
