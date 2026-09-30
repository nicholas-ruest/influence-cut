# influence-cut

`influence-cut` is a Rust CLI and library that turns a revocation request plus a
provenance DAG into a deterministic, content-addressed state-repair plan. It
finds every descendant of a revoked source, orders invalidation before
reconstruction, selects the latest clean checkpoint, and refuses to call a plan
executable when it reaches preserved state, unavailable systems, or committed
tool effects.

It is deliberately a planner. It does **not** claim that deleting one record
erases a concept, undo an email or payment, prove legal compliance, or perform
model-weight unlearning.

## Install

```console
$ cargo install --git https://github.com/nicholas-ruest/influence-cut
```

Or build from a checkout with stable Rust 1.85 or newer:

```console
$ cargo build --release
```

## Quick start

Validate a strict JSON provenance graph:

```console
$ cargo run -- validate --graph examples/agent-state.json
VALID nodes=7
```

Plan repair after a source is revoked:

```console
$ cargo run -- plan \
    --graph examples/agent-state.json \
    --request examples/revoke-preference.json
READY request=rev-2026-09-29-001 tenant=acme affected=5 checkpoint=checkpoint-0
  invalidate seq=6 node=draft-response
  invalidate seq=5 node=pending-plan
  invalidate seq=4 node=profile-vector
  invalidate seq=3 node=profile-summary
  invalidate seq=2 node=preference-source
  rebuild seq=3 node=profile-summary
  rebuild seq=4 node=profile-vector
  replay seq=5 node=pending-plan
  replay seq=6 node=draft-response
```

Use `--format json` for automation. The JSON includes a SHA-256 digest over the
entire normalized plan. Input object fields are strict: unknown fields fail
closed instead of being silently ignored.

## Model

Each node has a stable ID, tenant, monotonic sequence, kind, parent IDs, and a
repair mode:

- `invalidate`: remove or tombstone the affected state;
- `rebuild`: invalidate, then rebuild from repaired parents;
- `replay`: invalidate, then replay from the latest clean checkpoint;
- `compensate`: stop for a separately authorized compensating action;
- `unavailable`: report that the locus is outside the repair boundary;
- `preserve`: stop when affected state must be retained.

Source nodes cannot have parents. Other nodes require parents except standalone
checkpoints. Edges must stay within one tenant and move forward in sequence.
These rules make cycles and cross-tenant dependency leaks invalid before a plan
is produced.

Invalidations are emitted in reverse dependency order. Rebuild and replay steps
are emitted in forward order. A replay plan without a checkpoint before every
target is blocked. A `tool_effect` is always reported as a committed effect,
even if its declared repair mode is `compensate`.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Input is valid and the plan has no blockers |
| `1` | I/O, JSON, schema, graph, or request validation failed |
| `2` | A plan was produced but requires human or external resolution |

## Verification

```console
$ cargo fmt --check
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo test --all-features
$ cargo package --locked
```

The crate forbids unsafe Rust. CI repeats all four checks on every push and pull
request.

## Limitations

The planner trusts the completeness and accuracy of the supplied provenance
graph. A missing parent edge, replica, cache, model state, or external processor
cannot be discovered from graph structure alone. The plan digest proves only
that a specific plan document is unchanged; it is not a signature or proof that
the repair ran. Operators must separately authorize and execute repair,
compensation, retention, and audit workflows.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
