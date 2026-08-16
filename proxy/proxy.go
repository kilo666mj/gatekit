// Package proxy provides the protocol-neutral connection lifecycle shared by
// fingerprint gates. It parses LISTEN=BACKEND routes, accepts connections
// behind one global concurrency bound, tracks in-flight handlers, and drains
// them during shutdown or a zero-downtime binary handoff.
//
// Handshake inspection deliberately stays in each gate. SSH must relay both
// version strings and contact the backend before it can fingerprint KEXINIT;
// TLS can fingerprint entirely from the client's first records. Treating those
// as one Fingerprinter interface would hide materially different protocols.
package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kilo666mj/gatekit/semaphore"
)

// Route maps one listening address to one backend address. Port is derived
// from Listen when it is a valid host:port address, and is zero otherwise.
type Route struct {
	Listen  string
	Backend string
	Port    int
}

// ParseRoute parses a LISTEN=BACKEND route.
func ParseRoute(value string) (Route, error) {
	listen, backend, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(listen) == "" || strings.TrimSpace(backend) == "" {
		return Route{}, fmt.Errorf("route must be LISTEN=BACKEND, got %q", value)
	}
	port := 0
	if _, portText, err := net.SplitHostPort(listen); err == nil {
		port, _ = strconv.Atoi(portText)
	}
	return Route{Listen: listen, Backend: backend, Port: port}, nil
}

// Routes collects repeatable route flags.
type Routes []Route

func (r *Routes) String() string {
	parts := make([]string, len(*r))
	for i, route := range *r {
		parts[i] = route.Listen + "=" + route.Backend
	}
	return strings.Join(parts, ",")
}

// Set implements flag.Value.
func (r *Routes) Set(value string) error {
	route, err := ParseRoute(value)
	if err != nil {
		return err
	}
	*r = append(*r, route)
	return nil
}

// Handler owns protocol inspection and forwarding for one accepted
// connection. Server closes conn after Handler returns; closing it earlier is
// safe when a gate rejects a client.
type Handler func(conn net.Conn, route Route)

// LogFunc receives accept and overload messages. A nil function disables
// lifecycle logging; protocol decisions remain the consumer's responsibility.
type LogFunc func(format string, args ...any)

// Server shares one concurrency limit and drain set across every listener in a
// gate process.
type Server struct {
	sem      *semaphore.Semaphore
	logf     LogFunc
	acceptWG sync.WaitGroup
	connWG   sync.WaitGroup
}

// NewServer returns a connection server. maxConcurrent <= 0 is unbounded,
// which makes the zero configuration useful in tests and small consumers.
func NewServer(maxConcurrent int, logf LogFunc) *Server {
	var sem *semaphore.Semaphore
	if maxConcurrent > 0 {
		sem = semaphore.New(maxConcurrent)
	}
	return &Server{sem: sem, logf: logf}
}

// Serve starts accepting from ln and returns immediately. The caller closes ln
// to stop its accept loop before calling Drain.
func (s *Server) Serve(ln net.Listener, route Route, handler Handler) {
	s.acceptWG.Add(1)
	go func() {
		defer s.acceptWG.Done()
		s.serve(ln, route, handler)
	}()
}

func (s *Server) serve(ln net.Listener, route Route, handler Handler) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log("ACCEPT %s: %v", route.Listen, err)
			continue
		}
		clientIP := RemoteIP(conn.RemoteAddr())
		if !s.sem.Acquire() {
			s.log("[%s] OVERLOAD dropping connection on %s", clientIP, route.Listen)
			_ = conn.Close()
			continue
		}
		s.connWG.Add(1)
		go func() {
			defer s.connWG.Done()
			defer s.sem.Release()
			defer conn.Close()
			handler(conn, route)
		}()
	}
}

// Drain waits for all accept loops and connection handlers. It reports false
// when timeout expires. A timeout <= 0 waits indefinitely.
func (s *Server) Drain(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.acceptWG.Wait()
		s.connWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *Server) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

// RemoteIP returns the host portion of addr when it is a host:port address.
func RemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
