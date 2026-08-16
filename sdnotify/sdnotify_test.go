package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNotifyWithoutSocketIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
}

func TestReadyIncludesCurrentPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)

	if err := Ready(); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	message := string(buf[:n])
	if !strings.Contains(message, "READY=1") || !strings.Contains(message, "MAINPID="+strconv.Itoa(os.Getpid())) {
		t.Fatalf("message = %q", message)
	}
}

func TestNotifyReturnsSocketError(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	if err := Notify("READY=1"); err == nil {
		t.Fatal("Notify succeeded with a missing socket")
	}
}
