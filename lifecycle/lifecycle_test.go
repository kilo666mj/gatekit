package lifecycle

import (
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWatchSignalsUpgradesThenTerminates(t *testing.T) {
	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	controller := &fakeController{}
	var terminating atomic.Bool
	var logsMu sync.Mutex
	var logs []string
	finished := make(chan struct{})
	go func() {
		watchSignals(signals, done, controller, &terminating, func(format string, _ ...any) {
			logsMu.Lock()
			defer logsMu.Unlock()
			logs = append(logs, format)
		})
		close(finished)
	}()

	signals <- syscall.SIGHUP
	waitFor(t, func() bool { return controller.upgradeCount.Load() == 1 })
	if terminating.Load() {
		t.Fatal("SIGHUP marked manager terminating")
	}
	signals <- syscall.SIGTERM
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("signal loop did not stop")
	}
	if !terminating.Load() || controller.stopCount.Load() != 1 {
		t.Fatalf("terminating=%t stops=%d", terminating.Load(), controller.stopCount.Load())
	}
	logsMu.Lock()
	defer logsMu.Unlock()
	if len(logs) != 2 || !strings.Contains(logs[0], "upgrade") || !strings.Contains(logs[1], "shutting down") {
		t.Fatalf("logs = %q", logs)
	}
}

func TestWatchSignalsReportsUpgradeFailure(t *testing.T) {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	controller := &fakeController{upgradeErr: errors.New("boom")}
	var terminating atomic.Bool
	logged := make(chan string, 2)
	go watchSignals(signals, done, controller, &terminating, func(format string, _ ...any) { logged <- format })
	signals <- syscall.SIGHUP
	<-logged
	if got := <-logged; !strings.Contains(got, "upgrade failed") {
		t.Fatalf("log = %q", got)
	}
	close(done)
}

func TestWatchSignalsStopsWhenManagerCloses(t *testing.T) {
	signals := make(chan os.Signal)
	done := make(chan struct{})
	controller := &fakeController{}
	var terminating atomic.Bool
	finished := make(chan struct{})
	go func() {
		watchSignals(signals, done, controller, &terminating, nil)
		close(finished)
	}()
	close(done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("signal loop did not stop")
	}
}

type fakeController struct {
	upgradeCount atomic.Int32
	stopCount    atomic.Int32
	upgradeErr   error
}

func (f *fakeController) Upgrade() error {
	f.upgradeCount.Add(1)
	return f.upgradeErr
}

func (f *fakeController) Stop() { f.stopCount.Add(1) }

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met")
	}
}
