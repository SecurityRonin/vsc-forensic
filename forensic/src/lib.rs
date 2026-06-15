//! # vsc-forensic — Volume Shadow Copy anomaly auditor
//!
//! `vsc-forensic` is the planned analyzer half of the `vsc-forensic` workspace.
//! It will walk the shadow-copy snapshots decoded by [`vsc-core`](vsc) and emit
//! severity-graded [`forensicnomicon::report::Finding`]s — shadow-copy timeline
//! and integrity anomalies (missing or out-of-order snapshot timestamps,
//! catalog/store inconsistencies, deleted-store residue) — so VSS evidence
//! aggregates uniformly with every other artifact layer in a fleet `Report`.
//!
//! As the `[P^H]` disk-history layer, the snapshots it enumerates carry the
//! temporal cohort of a volume's state: each shadow copy is a point-in-time
//! materialization that the analyzer can diff against the live volume and
//! against its siblings.
//!
//! Status: early-stage scaffold; see docs/RESEARCH.md
//!
//! No public API is exported yet — the module skeletons below mark the planned
//! decomposition (anomaly kinds, the `audit` entry point) and will be filled in
//! once the VSS parser in `vsc-core` lands.

#![forbid(unsafe_code)]

/// Planned: the typed `AnomalyKind` enumeration for VSS findings, each mapping
/// to a published `VSC-*` finding code via `forensicnomicon::report`.
pub mod anomaly {}

/// Planned: the `audit` entry point — a pure, side-effect-free function over
/// already-decoded shadow-copy records that yields graded findings.
pub mod audit {}
