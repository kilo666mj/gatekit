// Package sdnotify sends process state to a systemd notification socket.
package sdnotify

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Ready tells a Type=notify unit that the current process is serving. MAINPID
// is included because a tableflip upgrade hands service to a child process
// that systemd must begin tracking. The unit therefore needs NotifyAccess=all.
func Ready() error {
	return Notify("READY=1\nMAINPID=" + strconv.Itoa(os.Getpid()))
}

// Notify sends state to NOTIFY_SOCKET. It is a no-op when the variable is
// unset. A leading '@' denotes Linux's abstract Unix socket namespace.
func Notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("dial notification socket: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("write notification: %w", err)
	}
	return nil
}
