package proxy

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseRoute(t *testing.T) {
	tests := []struct {
		value   string
		want    Route
		wantErr bool
	}{
		{value: "[::]:993=127.0.0.1:10993", want: Route{Listen: "[::]:993", Backend: "127.0.0.1:10993", Port: 993}},
		{value: "ssh.internal=backend.internal:22", want: Route{Listen: "ssh.internal", Backend: "backend.internal:22"}},
		{value: "missing-separator", wantErr: true},
		{value: "=backend:22", wantErr: true},
		{value: ":22=", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ParseRoute(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRoute() error = %v, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseRoute() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRoutesImplementsRepeatableFlag(t *testing.T) {
	var routes Routes
	if err := routes.Set(":22=127.0.0.1:2222"); err != nil {
		t.Fatal(err)
	}
	if err := routes.Set(":443=127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	if got := routes.String(); got != ":22=127.0.0.1:2222,:443=127.0.0.1:8443" {
		t.Fatalf("String() = %q", got)
	}
}

func TestServerBoundsConnectionsAndDrains(t *testing.T) {
	ln := newQueueListener()
	var logsMu sync.Mutex
	var logs []string
	server := NewServer(1, func(format string, args ...any) {
		logsMu.Lock()
		defer logsMu.Unlock()
		logs = append(logs, format)
	})
	started := make(chan struct{})
	release := make(chan struct{})
	server.Serve(ln, Route{Listen: ":22", Backend: "backend:22"}, func(_ net.Conn, _ Route) {
		close(started)
		<-release
	})

	serverOne, clientOne := net.Pipe()
	defer clientOne.Close()
	ln.send(serverOne)
	<-started

	serverTwo, clientTwo := net.Pipe()
	defer clientTwo.Close()
	ln.send(serverTwo)
	_ = clientTwo.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientTwo.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-capacity connection remained open")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("timed out waiting for over-capacity connection to close")
	}

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if !server.Drain(time.Second) {
		t.Fatal("server did not drain")
	}
	logsMu.Lock()
	defer logsMu.Unlock()
	if len(logs) != 1 || !strings.Contains(logs[0], "OVERLOAD") {
		t.Fatalf("logs = %q", logs)
	}
}

func TestDrainTimesOutForActiveHandler(t *testing.T) {
	ln := newQueueListener()
	server := NewServer(0, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	server.Serve(ln, Route{}, func(_ net.Conn, _ Route) {
		close(started)
		<-release
	})
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	ln.send(serverConn)
	<-started
	_ = ln.Close()
	if server.Drain(20 * time.Millisecond) {
		t.Fatal("Drain succeeded while handler was active")
	}
	close(release)
	if !server.Drain(time.Second) {
		t.Fatal("server did not drain after handler completed")
	}
}

func TestRemoteIP(t *testing.T) {
	if got := RemoteIP(&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}); got != "2001:db8::1" {
		t.Fatalf("RemoteIP() = %q", got)
	}
	if got := RemoteIP(nil); got != "" {
		t.Fatalf("RemoteIP(nil) = %q", got)
	}
}

type queueListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newQueueListener() *queueListener {
	return &queueListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *queueListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queueListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *queueListener) Addr() net.Addr { return fakeAddr("listener") }

func (l *queueListener) send(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.closed:
		_ = conn.Close()
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "test" }
func (a fakeAddr) String() string  { return string(a) }
