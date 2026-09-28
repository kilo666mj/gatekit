# Scoped fingerprint approvals: implementation design

Status: proposed implementation contract. This document does not enable scoped
approvals in any released gate. Existing unscoped approvals retain their behavior.

## Purpose and boundaries

A common TLS-library fingerprint is shared by unrelated clients. An operator
must be able to approve it only when the connection source also falls within a
specified set of CIDRs. Scope is an intersection with the fingerprint approval;
it is distinct from TLSGate trusted ranges, which bypass fingerprint policy.
Backend authentication remains required.

Gatekit owns parsing, persistence and synchronization. Gatehub owns decision
selection and the operator interface. TLSGate owns the forwarding verdict and
shadow-mode logs. Gatehub's existing instance/kind/global decision scope selects
**nodes**; the new approval scope restricts **client addresses**. Keep the two
concepts separate in APIs and labels.

## Data model and validation

Add `approval_ranges` to store entries, Gatehub decisions, observations and policy
responses. Missing or JSON null means unrestricted, for compatibility with old
unscoped records. A nonempty array of CIDR strings means restricted. An explicit
empty array is invalid; never silently interpret it as unrestricted. The UI must
provide a separate explicit action for removing all restrictions.

Parse with `net/netip`, reject hostnames, zone identifiers, malformed CIDRs and
IPv4-mapped IPv6 prefixes. Normalize accepted prefixes with `Masked`, deduplicate,
and sort deterministically. Accept IPv4 and IPv6 together, with OR semantics
inside the list. Unmap incoming IPv4-mapped addresses before matching IPv4
prefixes. A missing or unparsable connection address never matches a restriction.
Require at least one and at most 128 CIDRs; reject larger requests before storage.

Scopes apply only to approved decisions. Reject a non-null scope on pending or
blocked decisions. Changing a restricted approval to pending/blocked clears its
scope atomically. Reapproving without an explicit scope choice must not revive
or silently broaden the former approval. Existing status-only setters must
reject operations on a restricted approved entry when they cannot express this
choice; observation updates must always preserve the stored decision and scope.

## Storage and atomic policy application

Add a nullable JSON column through Gatekit's additive migration mechanism and
Gatehub's schema migration. Existing rows receive SQL NULL. Store validation
must run even for local callers, not just HTTP requests. Corrupt non-null stored
scope must return an error and cannot become an unrestricted approval.

Introduce one decision-write operation that changes status, label and scope in
one transaction. Do not apply `UpsertStatus` followed by a separate scope update:
that exposes a temporarily unrestricted approval to concurrent connections.
`Observe`, pruning and observation synchronization preserve operator scope.

Policy synchronization validates the complete returned batch first, then applies
its decisions and cursor in one transaction. On malformed scope, database error
or unsupported scope capability, retain the prior decisions and cursor and emit
a bounded error. Retrying a batch must be idempotent. Preserve existing decision
ordering and precedence; scopes are part of the selected decision, never unioned
across global, kind and instance decisions.

## Mixed-version protocol

An old client ignores unknown JSON fields. Adding a field alone is therefore
unsafe: it could receive an approved decision while discarding its restriction.
Add explicit node capability negotiation (`approval_ranges_v1`) before Gatehub
may send restricted approvals. The new Gatehub must reject creating a restricted
decision for any targeted node lacking this capability, including kind/global
targets. New node registration and capability changes revalidate applicable
restricted decisions. An incompatible policy pull must fail visibly rather than
serialize a restricted decision as an unrestricted approval.

A failed pull does not revoke an older cached unrestricted approval. Rollout must
therefore upgrade and verify every affected node **before** installing its first
restricted approval. A node must not advertise the capability until enforcement,
atomic storage and parsing are all present. Capability loss/downgrade with active
restricted approvals is prohibited operationally; stop the gate or first replace
those approvals with blocks and verify synchronization before rollback. Database
compatibility alone does not make an older binary safe to run.

## TLSGate decision order

Preserve the existing explicit trusted-range bypass and log it as `WHITELIST`.
The UI and operations guide must state that trusted ranges still bypass scoped
approval checks. An operator wanting an intersection must not put those clients
in trusted ranges merely to make the scoped approval work.

For all other clients, an approved unscoped fingerprint keeps current behavior.
An approved restricted fingerprint passes only when the source matches its CIDRs.
An out-of-scope approval is explicitly denied even on an observe/allow-unknown
listener; treating it as an ordinary unknown there would defeat the restriction.
Use a distinct `out_of_scope` log reason without changing the stored approval or
adding a blanket block. Ordinary pending/blocked behavior stays unchanged.

An opt-in shadow mode records `would_block_out_of_scope` while retaining the
previous forwarding result. Logs identify shadow/enforced mode and include the
existing fingerprint and client context, without treating shadow as enforcement.
Keep the hot path on parsed immutable prefix lists refreshed with policy changes;
never reuse a verdict cached solely by fingerprint for different client IPs.

## Implementation and verification sequence

1. Gatekit: typed scope parser, migration, atomic decision and cursor writes,
   store APIs and synchronization tests. Publish a tagged release.
2. TLSGate: pin that release, enforce matching, add shadow mode and explicit CLI
   scope choices. Do not advertise capability from storage-only intermediate code.
3. Gatehub: migrate decisions, API/UI validation, capability checks and visible
   scope display. Do not enable restricted writes before affected nodes upgrade.
4. Validate both gates against the released Gatekit, including SSHGate's unchanged
   unscoped behavior. Release and deploy with the existing Ansible workflow.
5. For the intended mail-client approval, verify the current source prefix through
   private deployment inventory, run shadow mode, review matching and nonmatching
   traffic, then enforce and verify backend receipt for the intended client.
   Keep actual client addresses and deployment identities out of public docs.

Required tests cover legacy-database migration; restart and scope retention;
null versus empty; invalid and oversized inputs; IPv4, IPv6 and mapped clients;
atomic writes and failed-batch cursor retention; preapproval before observation;
status changes; explicit scope removal; mixed-version rejection; decision
precedence; trusted bypass; observe versus strict listeners; shadow logging; and
two clients with the same fingerprint on opposite sides of the scope. Integration
checks must verify a rejected client never opens a backend connection.

Before live enforcement, record the running revisions, shadow evidence and a
rollback that uses blocks or a scope-aware prior binary. Reverting to a binary
that ignores scope would broaden an approval and is not a safe rollback.
