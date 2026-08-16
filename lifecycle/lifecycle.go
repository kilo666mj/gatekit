// Package lifecycle coordinates tableflip zero-downtime listener handoff and
// Unix process signals for a gate daemon.
package lifecycle

import (
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/cloudflare/tableflip"
)

// LogFunc receives lifecycle messages. A nil function disables logging.
type LogFunc func(format string, args ...any)

// Manager owns inherited listeners and the signal loop for one gate process.
type Manager struct {
	upgrader    *tableflip.Upgrader
	signals     chan os.Signal
	done        chan struct{}
	closeOnce   sync.Once
	terminating atomic.Bool
	logf        LogFunc
}

// New creates a tableflip upgrader and starts handling SIGHUP, SIGTERM, and
// SIGINT. SIGHUP re-execs the current binary and hands its listeners to the
// child; SIGTERM/SIGINT stop accepting and unblock Wait.
func New(logf LogFunc) (*Manager, error) {
	upgrader, err := tableflip.New(tableflip.Options{})
	if err != nil {
		return nil, err
	}
	m := &Manager{
		upgrader: upgrader,
		signals:  make(chan os.Signal, 1),
		done:     make(chan struct{}),
		logf:     logf,
	}
	signal.Notify(m.signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go watchSignals(m.signals, m.done, upgrader, &m.terminating, logf)
	return m, nil
}

// Listen returns an inherited or newly opened listener managed by tableflip.
func (m *Manager) Listen(network, address string) (net.Listener, error) {
	return m.upgrader.Listen(network, address)
}

// Ready declares that inherited listeners have been installed in this process.
func (m *Manager) Ready() error { return m.upgrader.Ready() }

// Wait blocks until a successful handoff or terminating signal asks this
// process to exit.
func (m *Manager) Wait() { <-m.upgrader.Exit() }

// Terminating distinguishes SIGTERM/SIGINT from an upgrade handoff so callers
// can choose an appropriate connection-drain deadline.
func (m *Manager) Terminating() bool { return m.terminating.Load() }

// Close stops signal delivery and the underlying upgrader. It is idempotent.
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		signal.Stop(m.signals)
		close(m.done)
		m.upgrader.Stop()
	})
}

type upgradeController interface {
	Upgrade() error
	Stop()
}

func watchSignals(signals <-chan os.Signal, done <-chan struct{}, controller upgradeController, terminating *atomic.Bool, logf LogFunc) {
	for {
		select {
		case <-done:
			return
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				log(logf, "SIGHUP: starting upgrade")
				if err := controller.Upgrade(); err != nil {
					log(logf, "upgrade failed: %v", err)
				}
				continue
			}
			log(logf, "%s: shutting down", sig)
			terminating.Store(true)
			controller.Stop()
			return
		}
	}
}

func log(logf LogFunc, format string, args ...any) {
	if logf != nil {
		logf(format, args...)
	}
}
