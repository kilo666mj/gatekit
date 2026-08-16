# gatekit

Shared node-side library for fingerprint gates.

A *gate* is a small TCP proxy that passively fingerprints a client's plaintext
handshake before forwarding it to the real backend, and uses that fingerprint
as a noise filter: known-good clients pass, unknown ones are recorded for
review, blocked ones are dropped. [`sshgate`](https://github.com/kilo666mj/sshgate)
does this for the SSH `KEXINIT` (HASSH-style); [`tlsgate`](https://github.com/kilo666mj/tlsgate)
does it for the TLS ClientHello (JA3/JA4).

Both had independently grown the same ~1,500 lines: a SQLite fingerprint store,
a gatehub sync client, a per-IP token bucket, and a concurrency cap. gatekit is
that spine, factored out once.

It is **not** a control plane — that's [`gatehub`](https://github.com/kilo666mj/gatehub).
gatekit is what runs on the node and talks to it.

## Packages

| Package | What it provides |
|---|---|
| `store` | SQLite fingerprint store: entries, verdicts, labels, per-fingerprint IP/port sighting lists, sighting counts, pruning, and a protocol-agnostic metadata bag |
| `controlplane` | gatehub sync client — pushes observations, pulls and applies policy |
| `ratelimit` | Per-source-IP token bucket, IPv6-masked to /64, with a bounded bucket map |
| `semaphore` | Global concurrency cap for in-flight connections |
| `proxy` | `LISTEN=BACKEND` routes, bounded accept loops, connection tracking, and graceful drain |
| `sdnotify` | systemd readiness notification with tableflip child-PID handoff support |
| `lifecycle` | tableflip listener inheritance plus SIGHUP upgrade and terminating-signal coordination |

## Protocol metadata

The store deliberately does not know about SSH or TLS. Each entry carries a
`Meta map[string]any` that the gate fills with whatever its fingerprinter
produced — `kex`/`cipher_c2s`/`host_key` for SSH, `sni`/`alpn`/`ja4` for TLS —
persisted as one JSON column. The same bag rides through to gatehub as the
observation's `metadata` field, which is why one sync client can serve every
gate and a new gate needs no schema change.

```go
st, err := store.Open(store.Options{Path: "/var/lib/mygate/db.sqlite"})
if err != nil {
    return err
}
defer st.Close()

entry, err := st.Observe(store.Observation{
    Fingerprint: fp.Hash,
    IP:          clientIP,
    Port:        localPort,
    Meta:        map[string]any{"sni": fp.SNI, "alpn": fp.ALPN},
}, allowUnknown == false)
if err != nil {
    return err
}
if entry.Status == store.StatusBlocked {
    return errBlocked
}
```

`Observe` inserts on first sight and, on every later sight, refreshes only
`last_seen`, the sighting count, and the metadata bag. Status, label, and
`first_seen` are left alone, so an operator's verdict survives re-observation —
and a verdict written ahead of time by `UpsertStatus` (how gatehub pre-approves
a fingerprint on a fresh node) survives the client's first real connection.

Verdict and label are separate operations — `SetStatus(fp, status)` and
`SetLabel(fp, label)`. Folding them into one call means an operator who
re-approves a fingerprint without repeating its label silently blanks it,
losing the annotation that makes the row identifiable. `UpsertStatus` does take
both, because the control plane is authoritative for both.

## Migrating an existing gate database

sshgate and tlsgate both have databases in service, with protocol fields in
dedicated typed columns. Pass a `Legacy` mapping and `Open` folds those values
into the metadata bag exactly once:

```go
st, err := store.Open(store.Options{
    Path: "/var/lib/tlsgate/db.sqlite",
    Legacy: []store.LegacyColumn{
        {Column: "ja3", MetaKey: "ja3"},
        {Column: "sni", MetaKey: "sni"},
        {Column: "alpn", MetaKey: "alpn", Kind: store.KindJSON},
    },
})
```

The migration is designed to be boring in the ways that matter:

- **Approvals, blocks, labels, first-seen dates and sighting lists are
  preserved.** They live in columns gatekit already understands.
- **It runs once**, guarded by a marker in the `meta` table, so metadata the
  gate has refreshed since is never reverted on a restart.
- **It never clobbers** a key already present in the bag.
- **The legacy columns are left in place.** They all carry defaults, so
  gatekit's inserts ignore them — which means rolling back to the pre-gatekit
  binary finds its schema intact. Rollback is a binary swap, not a restore.

`store/legacy_test.go` exercises this against verbatim copies of both gates'
production schemas.

## Status

**v0.3** — store, control plane, rate limiter, semaphore, proxy lifecycle,
systemd readiness notification, and tableflip lifecycle coordination are
shared by sshgate and tlsgate.

The shared proxy package intentionally stops at route parsing, bounded accept,
connection tracking, and drain. SSH must relay version strings and contact its
backend before it can fingerprint KEXINIT, while TLS fingerprints from the
client's first records; one `Fingerprinter` interface would conceal that real
protocol difference rather than remove duplication.

Not yet extracted: bidirectional stream helpers, CLI behavior, and shared
deployment assets. The stream semantics and CLI commands currently differ in
meaningful protocol-specific ways, so they should not move merely to reduce a
line count. Deployment assets can follow after the shared runtime has been
proven by both production gates.

## License

MIT
