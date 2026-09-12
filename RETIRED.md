# RETIRED 2026-09-12 — never consumed; kept as a historical reference

The org decided the same day to go per-project: each app maintains its
own Rust core in its own repo (conch absorbed this repo's ssh-transport
back into conch/shared/ssh-transport; the conch-owned FFI boundary is
conch/shared/ssh-ffi). No repo consumes this one. The public code is
freely copyable by the org's own projects as a starting point.

The rules recorded in PLAN.md (pure crates, fixture-oracle parity,
exact pins, consumer-count thinking) remain good practice for
whichever repo inherits them.
