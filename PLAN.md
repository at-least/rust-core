# PLAN.md — rust-core: status & forward plan

Relocated 2026-09-12 from conch's `PLAN.md` §3.6 (the org Rust-core
program; S1 ran in conch, S2 is this repo's birth). The ownership line
and decisions live in conch's `shared/specs/rust-core.md` §6 — this file
is the execution state. If something here conflicts with reality,
reality wins — verify, then fix this file.

## 0. Workflow

- Development on `main`. Single-purpose commits; the message asserts
  only what its evidence demonstrated.
- Apps consume by pinned rev from their own ffi crates; a rev bump in an
  app is a deliberate, separate change with its own gates.
- Before declaring a stage done: `consult_advisor` checkpoint;
  `review_change` for risky diffs.

## 1. Stages

| Stage | Scope | State |
|---|---|---|
| S1 | in-conch workspace split of `ssh_spike.rs` (proved the seam, its own UniFFI namespace) | done 2026-09-12, conch `7dd365f` |
| S2 | this repo is born: `ssh-transport` + the Rust-level sshd matrix move here; conch switches to a pinned-rev git dep | done 2026-09-12 |
| S3 | own-music pure logic core (`music-core`: scanner/parsers/canonical JSON/sync rules) — single consumer, stays in own-music | plan: own-music `PLAN.md` §13 |
| S4 | own-music providers + storage (rusqlite, HttpExecutor/TokenStore callbacks) | plan: own-music `PLAN.md` §13 |
| S5 | `terminal-engine` extraction (from conch) + `bbs-core` (pttinapp; pre-gates: ptt.cc kex probe, dual-color CJK render probe — pttinapp `PLAN.md`) | plan: pttinapp `PLAN.md` |
| S6 | own-video `video-transfer` (protocol logic; socket stays native unless a parity bug) — single consumer, stays in own-video | plan: own-video `PLAN.md` |

Per-stage detail lives in the consuming repo's PLAN.md; this file
records what has landed here and what moves here next.

## 2. Ownership line (adjudicated — do not re-open)

**Rust owns what has or can have a golden-fixture test; native owns what
touches a platform lifecycle, permission, or background-execution API.**
FFI surfaces are data-in/data-out plus event sinks; Rust never holds a
platform resource it cannot own end to end. HTTP byte transfer, OAuth
interactive flows, and token storage are platform-side
`HttpExecutor`/`TokenStore` callbacks — never reqwest in the core.

## 3. Standing rules

1. Never delete a native core until the Rust candidate passes the SAME
   fixtures AND a parity CI job runs both.
2. Exact dependency pins (`=x.y.z`) and a committed `Cargo.lock` — the
   repo must build reproducibly everywhere.
3. A UniFFI bridge-version constant per namespace, exported through the
   FFI, so a stale committed binding fails loudly.
4. A crate lands here only with its verification story: fixture oracle,
   CI gates (fmt/clippy/test), and for the transport, the sshd matrix
   (`tools/sshd-matrix`, env-gated with `CONCH_SSHD_MATRIX_REQUIRED=1`
   in CI so a down matrix FAILS instead of skipping green).
5. **A crate lands here when (and only when) a second REPO needs to
   depend on it** (repos, not platforms — pttinapp's two apps are one
   consumer). Single-consumer crates stay in their app's repo: conch
   keeps terminal-core in-conch, own-music keeps music-core,
   own-video keeps video-transfer. Promotion is cheap when a second
   consumer appears — the S2 mechanics, already proven.
6. Out of scope, do not re-propose: telnet:23, CI-published artifact
   registries, per-domain repos for the shared crates, PttProbe,
   moving the Go backend.

## 4. Environment facts

- CI: `.github/workflows/ci.yml` — the rust job (fmt/clippy/test) and
  the matrix job (docker sshd up + the transport suite, which needs live
  servers only at RUNTIME).
- The transport's UniFFI namespace is `ssh_transport`; its Kotlin
  bindings pin `cdylib_name` to the consuming app's cdylib (conch:
  `terminal_core`) via `ssh-transport/uniffi.toml`, and its Swift FFI
  module merges into the consumer's module via `ffi_module_name`.
