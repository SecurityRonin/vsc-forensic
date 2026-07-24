# 8. Findings are graded observations via `forensicnomicon::report`, never verdicts

Date: 2026-07-24
Status: Accepted

## Context

`vsc-forensic` must report shadow-copy anomalies in a way that (1) aggregates
uniformly with every other fleet analyzer, and (2) never overstates. An absence
of shadow copies is the classic overreach trap: it is *consistent with* MITRE
T1490 shadow-copy deletion, but it is equally consistent with a volume that never
had snapshots. Asserting deletion would be a legal/investigative conclusion the
analyzer has no basis to make — the fleet epistemology (observed fact vs
inference vs conclusion; "name the observable, not the conclusion") forbids it.

The fleet Reporting Model (`forensicnomicon::report`) is the single normalized
finding vocabulary every analyzer emits, so ORCHESTRATION (issen, disk4n6) renders
all findings uniformly. The producer pattern is: keep the analyzer's own typed
`AnomalyKind` (domain knowledge) and convert to canonical `Finding`s.

## Decision

1. **Keep a typed `AnomalyKind` enum** (`forensic/src/lib.rs`) as the analyzer's
   domain model, and convert to `forensicnomicon::report::Finding` via the
   `Observation` pattern — the reader/analyzer keeps its knowledge, the report
   crate does not enumerate every VSS anomaly.
2. **Every finding is an observation graded by severity**, not a verdict. The
   four codes and their grades are the published contract (scheme-prefixed
   SCREAMING-KEBAB, `code()` returns `&'static str`):
   - `VSC-NO-SHADOW-COPIES` — `Low`, `Category::History`
   - `VSC-STORE-PRESENT` — `Info`, `Category::History` (one per store)
   - `VSC-SEQUENCE-GAP` — `Medium`, `Category::Residue`
   - `VSC-STORE-NON-PERSISTENT` — `Low`, `Category::Provenance`
3. **"Consistent with," never "confirms."** The `NoShadowCopies` note reads
   "consistent with shadow-copy deletion (MITRE T1490) or a volume that never had
   snapshots — not a determination of deletion" (`forensic/src/lib.rs`), and the
   MITRE reference is carried as an `ExternalRef`, framed as consistency, not a
   conclusion.
4. **Findings surface the offending values** — `VSC-STORE-PRESENT` carries the
   store GUID, sequence, size, and creation time; `VSC-SEQUENCE-GAP` carries the
   bracketing sequence numbers — so the note hands the analyst the evidence, per
   the fleet "show the value" robustness rule.
5. **Severity is single-sourced** on `AnomalyKind::severity()`, so a code and its
   grade cannot drift apart.

## Consequences

- `vsc-forensic` output drops into a fleet `Report` beside every other analyzer
  with no bespoke rendering, because it speaks only the shared report model.
- The analyzer never asserts deletion or any legal conclusion — the analyst or
  tribunal draws it, which the "consistent with" wording enforces at the source.
- The four `VSC-*` codes are a stable published contract: a shipped code is never
  changed; new anomaly kinds get new codes (fleet convention).
- `AnomalyKind` is `#[non_exhaustive]`-friendly domain data; adding a kind is an
  additive change to the analyzer and one new code, not a fleet-wide break.
