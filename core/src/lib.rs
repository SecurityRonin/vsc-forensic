//! # vsc-core — Windows Volume Shadow Copy (VSS) reader
//!
//! `vsc-core` is the planned reader half of the `vsc-forensic` workspace: a
//! panic-free decoder for the on-disk structures of Windows Volume Shadow Copy
//! (VSS), the `[P^H]` disk-history substrate of the forensic fleet.
//!
//! The aim is to navigate a raw NTFS volume's VSS region by snapshot — locating
//! the VSS volume header, walking the catalog of shadow-copy stores, and
//! enumerating each store's block list so a consumer can diff filesystem state
//! across point-in-time snapshots. The reader stays pure: it decodes bytes and
//! exposes typed records, making no forensic judgments (those live in the
//! sibling `vsc-forensic` analyzer crate).
//!
//! Status: early-stage scaffold; see docs/RESEARCH.md
//!
//! No public API is exported yet — the module skeletons below mark the planned
//! decomposition (catalog, store, block list) and will be filled in as the VSS
//! parser is implemented.

#![forbid(unsafe_code)]

/// Planned: VSS volume header and catalog (`{3808876b-...}`) decoding —
/// locating the catalog and enumerating shadow-copy store entries.
pub mod catalog {}

/// Planned: VSS store decoding — store header, block descriptors, and the
/// block list that maps original volume blocks to snapshot copies.
pub mod store {}

/// Planned: block-list navigation — resolving a snapshot's view of the volume
/// by overlaying copied blocks on the live volume.
pub mod block {}
