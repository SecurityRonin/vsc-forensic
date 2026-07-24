# 1. Two-crate reader/analyzer split (`vsc-core` + `vsc-forensic`)

Date: 2026-07-24
Status: Accepted

## Context

`vsc-forensic` decodes the on-disk structures of Windows Volume Shadow Copy
(VSS) and surfaces shadow-copy timeline/integrity anomalies. Two concerns live
in one repo: (1) faithfully *reading* the VSS catalog/store/block structures out
of an untrusted NTFS volume, and (2) *judging* what those records mean
forensically. A reader that only decodes bytes is reusable by anyone who needs
VSS structures; an analyzer that emits graded findings is only useful to the
DFIR pipeline. Fusing the two would force every consumer of the raw records to
pull the finding model, and would let forensic policy leak into the byte
decoder.

The fleet Crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates, for a single-format repo named
`<x>-forensic`, exactly two members: `core/` → `<x>-core` (the raw reader,
no findings) and `forensic/` → `<x>-forensic` (the anomaly auditor emitting
`forensicnomicon::report::Finding`). This is Pattern A of the naming grammar.

## Decision

Ship a workspace with two members (`Cargo.toml` `members = ["core", "forensic"]`):

1. **`core/` → crate `vsc-core`** — the reader. It parses the VSS volume header,
   catalog, store metadata, diff-area records, and reconstructs snapshots. It
   emits typed records only and makes no forensic judgment. Its doc header
   states the contract: "The reader stays pure: it decodes bytes into typed
   records and makes no forensic judgments" (`core/src/lib.rs`).
2. **`forensic/` → crate `vsc-forensic`** — the analyzer. It walks the stores
   `vsc-core` decoded and emits severity-graded `Finding`s
   (`forensic/src/lib.rs`). It is a side-effect-free function of already-decoded
   records.
3. **Dependency direction is strictly downward.** `vsc-forensic` depends on
   `vsc-core` + `forensicnomicon`; `vsc-core` depends only on `uuid` +
   `thiserror` (member `Cargo.toml`s). The reader never depends on the analyzer
   or on the finding model.

Repo introduced this shape from the first working code: commit `10218a9`
("GREEN — vsc-core VSS reader") and `08f3133` ("GREEN — vsc-forensic VSS anomaly
auditor").

## Consequences

- `vsc-core` is independently useful — a consumer that wants VSS structures (or
  snapshot reconstruction) links it without any finding-model dependency.
- `vsc-forensic` drops straight into a fleet `Report` beside every other
  analyzer, because it speaks only `forensicnomicon::report`.
- Forensic policy (severities, MITRE framing, "consistent with" wording) is
  confined to one crate; the byte decoder cannot drift into making verdicts.
- Two crates are published and versioned together (shared `[workspace.package]`
  version `0.2.0`), so a reader change and the analyzer that consumes it release
  in lockstep via release-plz.
