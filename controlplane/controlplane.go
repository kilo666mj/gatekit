// Package controlplane implements the gate side of the gatehub sync protocol:
// it pushes observed fingerprints upstream and applies the verdicts gatehub
// sends back.
package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kilo666mj/gatekit/store"
)

const (
	// DefaultSyncInterval is how often a gate syncs when unconfigured.
	DefaultSyncInterval = 30 * time.Second
	// maxObservationValues caps the per-fingerprint IP and port lists in a
	// pushed observation, so one heavily-scanned fingerprint cannot inflate
	// the batch without bound.
	maxObservationValues = 128
)

// Config is the control_plane block of a gate's config file.
type Config struct {
	URL          string `json:"url"`
	InstanceID   string `json:"instance_id"`
	Token        string `json:"token"`
	ClientCert   string `json:"client_cert"`
	ClientKey    string `json:"client_key"`
	CA           string `json:"ca"`
	ServerName   string `json:"server_name"`
	SyncInterval string `json:"sync_interval"`
}

// Enabled reports whether a control plane is configured at all.
func (cfg Config) Enabled() bool { return strings.TrimSpace(cfg.URL) != "" }

// Validate checks the config is usable before a gate starts.
func (cfg Config) Validate() error {
	if cfg.InstanceID == "" {
		return fmt.Errorf("control_plane.instance_id is required")
	}
	if cfg.Token == "" && (cfg.ClientCert == "" || cfg.ClientKey == "" || cfg.CA == "") {
		return fmt.Errorf("control_plane.token or client_cert, client_key, and ca are required")
	}
	if _, err := url.ParseRequestURI(cfg.URL); err != nil {
		return fmt.Errorf("control_plane.url: %w", err)
	}
	if cfg.SyncInterval != "" {
		if _, err := time.ParseDuration(cfg.SyncInterval); err != nil {
			return fmt.Errorf("control_plane.sync_interval: %w", err)
		}
	}
	return nil
}

// Interval is the configured sync period, or DefaultSyncInterval.
func (cfg Config) Interval() time.Duration {
	if cfg.SyncInterval == "" {
		return DefaultSyncInterval
	}
	d, err := time.ParseDuration(cfg.SyncInterval)
	if err != nil || d <= 0 {
		return DefaultSyncInterval
	}
	return d
}

type observation struct {
	Fingerprint string           `json:"fingerprint"`
	Status      store.Status     `json:"status"`
	Label       string           `json:"label,omitempty"`
	FirstSeen   string           `json:"first_seen,omitempty"`
	LastSeen    string           `json:"last_seen,omitempty"`
	IPs         []string         `json:"ips,omitempty"`
	Ports       []int            `json:"ports,omitempty"`
	Sightings   []store.Sighting `json:"sightings,omitempty"`
	Count       int              `json:"count,omitempty"`
	Metadata    map[string]any   `json:"metadata,omitempty"`
}

type observationBatch struct {
	InstanceID   string        `json:"instance_id"`
	Observations []observation `json:"observations"`
}

type policyResponse struct {
	Cursor    string     `json:"cursor,omitempty"`
	Decisions []decision `json:"decisions"`
}

type decision struct {
	Fingerprint string       `json:"fingerprint"`
	Status      store.Status `json:"status"`
	Label       string       `json:"label,omitempty"`
	UpdatedAt   string       `json:"updated_at,omitempty"`
}

// Syncer pushes observations to gatehub and applies returned policy.
type Syncer struct {
	store  *store.Store
	cfg    Config
	client *http.Client
	cursor string
}

// New builds a Syncer. Callers should Validate the config first.
func New(st *store.Store, cfg Config) (*Syncer, error) {
	client, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Syncer{store: st, cfg: cfg, client: client}, nil
}

// Start begins syncing in the background until ctx is cancelled. It is a no-op
// when no control plane is configured, so gates can call it unconditionally.
func Start(ctx context.Context, st *store.Store, cfg Config) error {
	if !cfg.Enabled() {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	s, err := New(st, cfg)
	if err != nil {
		return err
	}
	interval := cfg.Interval()
	log.Printf("gatehub sync enabled: instance=%s url=%s interval=%s", cfg.InstanceID, cfg.URL, interval)
	go s.Run(ctx, interval)
	return nil
}

// Run syncs immediately, then every interval until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	s.SyncOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SyncOnce()
		}
	}
}

// SyncOnce performs one push/pull cycle, logging rather than returning errors
// so a transient gatehub outage never stops the loop.
func (s *Syncer) SyncOnce() {
	if err := s.PushObservations(); err != nil {
		log.Printf("gatehub observation sync: %v", err)
	}
	if err := s.PullPolicy(); err != nil {
		log.Printf("gatehub policy sync: %v", err)
	}
}

// PushObservations uploads every stored fingerprint as an observation batch.
func (s *Syncer) PushObservations() error {
	entries, err := s.store.List()
	if err != nil {
		return err
	}
	batch := observationBatch{InstanceID: s.cfg.InstanceID}
	for fp, entry := range entries {
		batch.Observations = append(batch.Observations, toObservation(fp, entry))
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	endpoint, err := endpointURL(s.cfg.URL, "/v1/observations/batch", s.cfg.InstanceID, "")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	s.setAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("POST observations returned %s (instance %q not registered with gatehub?)", resp.Status, s.cfg.InstanceID)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST observations returned %s", resp.Status)
	}
	return nil
}

// PullPolicy fetches verdicts since the last cursor and applies them locally.
func (s *Syncer) PullPolicy() error {
	endpoint, err := endpointURL(s.cfg.URL, "/v1/policy", s.cfg.InstanceID, s.cursor)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	s.setAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("GET policy returned %s (instance %q not registered with gatehub?)", resp.Status, s.cfg.InstanceID)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET policy returned %s", resp.Status)
	}
	var policy policyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return err
	}
	for _, d := range policy.Decisions {
		if d.Fingerprint == "" {
			continue
		}
		if !d.Status.Valid() {
			log.Printf("gatehub policy ignored invalid status %q for %s", d.Status, d.Fingerprint)
			continue
		}
		if err := s.store.UpsertStatus(d.Fingerprint, d.Status, d.Label); err != nil {
			return fmt.Errorf("apply decision for %s: %w", d.Fingerprint, err)
		}
	}
	if policy.Cursor != "" {
		s.cursor = policy.Cursor
	}
	return nil
}

func (s *Syncer) setAuth(req *http.Request) {
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
}

// toObservation maps a stored entry onto the wire format. The protocol-specific
// fields ride along in Metadata exactly as the gate wrote them to the store,
// which is what lets one syncer serve every gate.
func toObservation(fp string, entry store.Entry) observation {
	return observation{
		Fingerprint: fp,
		Status:      entry.Status,
		Label:       entry.Label,
		FirstSeen:   entry.FirstSeen.UTC().Format(time.RFC3339Nano),
		LastSeen:    entry.LastSeen.UTC().Format(time.RFC3339Nano),
		IPs:         limited(entry.IPs, maxObservationValues),
		Ports:       limited(entry.Ports, maxObservationValues),
		Sightings:   limited(entry.Sightings, maxObservationValues),
		Count:       entry.Count,
		Metadata:    entry.Meta,
	}
}

func limited[T any](values []T, max int) []T {
	if max <= 0 || len(values) <= max {
		return values
	}
	out := make([]T, max)
	copy(out, values[:max])
	return out
}

func newHTTPClient(cfg Config) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.ServerName,
	}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if cfg.CA != "" {
		caPEM, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no CA certificates found in %s", cfg.CA)
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

func endpointURL(base, path, instanceID, since string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	q := u.Query()
	q.Set("instance_id", instanceID)
	if since != "" {
		q.Set("since", since)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
