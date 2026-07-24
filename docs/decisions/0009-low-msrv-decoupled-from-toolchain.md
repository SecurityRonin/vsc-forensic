# 9. Low declared MSRV (1.81) decoupled from the pinned dev toolchain (1.96.0)

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates two things that are easy to conflate: the **dev
toolchain** (what contributors build/fmt/clippy with) and the **declared MSRV**
(`rust-version`, a downstream-facing compatibility promise). Published *libraries*
keep a low, CI-verified MSRV as a deliberate reuse feature; only *apps* pin their
declared MSRV to the dev toolchain. `vsc-core` and `vsc-forensic` are libraries
(others link them; nothing pins a library dependency against them), so they take
the low-MSRV floor, not the toolchain pin.

## Decision

1. **Pin the dev toolchain to the current fleet stable** — `rust-toolchain.toml`
   `channel = "1.96.0"` with `clippy` + `rustfmt` components — so all contributors
   and CI share one toolchain and fmt/clippy do not churn.
2. **Declare a low MSRV of `1.81`** — `[workspace.package] rust-version = "1.81"`
   (root `Cargo.toml`), inherited by both members and advertised by the README
   `Rust 1.81+` badge. This is the compatibility promise, deliberately below the
   dev toolchain, so third-party consumers on an older stable can still link the
   crates.
3. **These two numbers are intentionally different** and must not be conflated —
   raising `rust-version` narrows the crates.io audience and is treated as a
   near-breaking change, done only when a genuinely-needed newer-Rust feature
   forces it, never merely to match the toolchain.

## Consequences

- The reader stays broadly linkable (Rust 1.81+) while development happens on the
  newer pinned stable.
- CI must keep a low-MSRV verification job honest against the `1.81` floor; a
  language/dependency feature that would push the floor higher is a deliberate,
  reasoned bump, not an accident of the dev toolchain.
- **Rationale for the specific floor being `1.81` (rather than the fleet's more
  common `1.75`/`1.80`) is reconstructed from structure; the exact
  language/dependency feature that forced `1.81` over `1.80` is not recovered from
  available history.** The load-bearing decision — a low MSRV decoupled from the
  pinned toolchain — is fully grounded; only the precise driver of the `1.81`
  value is undetermined.
