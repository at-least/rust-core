# rust-core

The Rust crates shared by the at-least apps. Private app logic ships as
thin per-app `ffi` crates that pin a rev of this repo; nothing here is
consumed by path from an app repo, and app repos never depend on app
repos.

| Crate | What it is | UniFFI namespace | Consumed by |
|---|---|---|---|
| `ssh-transport` | russh transport + SFTP + host-key blob helpers | `ssh_transport` | conch (today); own-music, own-video (SFTP, when their stages start) |
| `terminal-engine` | alacritty/vte engine (planned — S5, extracted from conch) | `terminal_engine` | conch, pttinapp |
| `bbs-core` | BBS flows over a `Screen` trait (planned — S5) | — | pttinapp |
| `music-core` | sync engine, parsers, providers' logic (planned — S3/S4, from own-music) | — | own-music |
| `video-transfer` | transfer protocol logic (planned — S6, from own-video) | — | own-video |

Discipline (see PLAN.md): exact dependency pins, committed `Cargo.lock`,
fixture-oracle parity before any incumbent is deleted, and a bridge
version constant per UniFFI namespace so a stale committed binding fails
loudly.
