//! # vsc-forensic — Volume Shadow Copy anomaly auditor
//!
//! Walks the shadow-copy stores decoded by [`vsc`](vsc) and emits severity-graded
//! [`forensicnomicon::report::Finding`]s. Findings are OBSERVATIONS, never
//! verdicts: an absence of shadow copies is reported as *consistent with* MITRE
//! T1490 deletion **or** a volume that simply never had snapshots — the analyzer
//! does not assert deletion.
//!
//! As the `[P^H]` disk-history layer, each enumerated store is a point-in-time
//! materialization of the volume; the analyzer surfaces their presence, catalog
//! sequence gaps (consistent with a deleted intermediate store), and notable
//! store attributes.
//!
//! ```no_run
//! use std::fs::File;
//! use vsc::VssVolume;
//!
//! let mut vol = VssVolume::open(File::open("volume.raw")?)?;
//! for anomaly in vsc_forensic::audit(&mut vol) {
//!     println!("{}: {}", anomaly.code, anomaly.note);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{Read, Seek};

use forensicnomicon::report::{
    Category, Evidence, Finding, Observation, Severity, Source, SubjectRef, Timestamp,
};
use vsc::VssVolume;

#[cfg(test)]
mod tests;

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "vsc-forensic";

/// Difference between the Windows FILETIME epoch (1601-01-01) and the Unix epoch
/// (1970-01-01), in 100 ns units.
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// A classified VSS forensic anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// The volume carries a VSS volume header but the catalog enumerated zero
    /// stores — consistent with shadow-copy deletion (T1490) OR a volume that
    /// never had snapshots. Not a determination of deletion.
    NoShadowCopies,
    /// A shadow-copy store is present.
    StorePresent {
        /// Store identifier GUID (canonical string).
        store_id: String,
        /// Catalog sequence number.
        sequence: u64,
        /// Shadow-copy volume size at snapshot time.
        volume_size: u64,
        /// Raw creation-time FILETIME.
        creation_time: u64,
    },
    /// Catalog sequence numbers are non-contiguous — consistent with a deleted
    /// intermediate shadow copy.
    SequenceGap {
        /// The lower sequence number bracketing the gap.
        previous: u64,
        /// The next present sequence number.
        next: u64,
    },
    /// A store lacks the persistent attribute — a non-persistent shadow copy
    /// does not survive a reboot, which is unusual for on-disk VSS.
    StoreNonPersistent {
        /// Store identifier GUID (canonical string).
        store_id: String,
        /// The store's attribute flags.
        attribute_flags: u32,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        let _ = self;
        unimplemented!("RED: AnomalyKind::severity")
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        let _ = self;
        unimplemented!("RED: AnomalyKind::code")
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        let _ = self;
        unimplemented!("RED: AnomalyKind::category")
    }

    /// Human-readable, "consistent with" note including the offending values.
    #[must_use]
    pub fn note(&self) -> String {
        let _ = self;
        unimplemented!("RED: AnomalyKind::note")
    }

    /// MITRE ATT&CK technique ids this kind is consistent with.
    #[must_use]
    pub fn mitre(&self) -> &'static [&'static str] {
        let _ = self;
        unimplemented!("RED: AnomalyKind::mitre")
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let _ = self;
        unimplemented!("RED: AnomalyKind::subjects")
    }

    fn evidence(&self) -> Vec<Evidence> {
        let _ = self;
        unimplemented!("RED: AnomalyKind::evidence")
    }

    fn timestamps(&self) -> Vec<Timestamp> {
        let _ = self;
        unimplemented!("RED: AnomalyKind::timestamps")
    }
}

/// A VSS forensic anomaly: an observation graded by severity, with a stable code
/// and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        let _ = kind;
        unimplemented!("RED: Anomaly::new")
    }

    /// Assemble the canonical [`Finding`], adding the FILETIME-derived timestamps
    /// the [`Observation`] trait cannot carry on its own.
    #[must_use]
    pub fn to_finding(&self, source: Source) -> Finding {
        let _ = source;
        unimplemented!("RED: Anomaly::to_finding")
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        unimplemented!("RED: Observation::severity")
    }
    fn code(&self) -> &'static str {
        unimplemented!("RED: Observation::code")
    }
    fn note(&self) -> String {
        unimplemented!("RED: Observation::note")
    }
    fn category(&self) -> Category {
        unimplemented!("RED: Observation::category")
    }
    fn subjects(&self) -> Vec<SubjectRef> {
        unimplemented!("RED: Observation::subjects")
    }
    fn evidence(&self) -> Vec<Evidence> {
        unimplemented!("RED: Observation::evidence")
    }
    fn mitre(&self) -> &'static [&'static str] {
        unimplemented!("RED: Observation::mitre")
    }
}

/// Convert a raw Windows FILETIME to an RFC 3339 string, or `None` when the value
/// is zero or predates the Unix epoch.
#[must_use]
pub fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    let _ = filetime;
    unimplemented!("RED: filetime_to_rfc3339")
}

/// Audit the shadow copies of a VSS volume, returning classified anomalies.
///
/// Reads each store's information to inspect attribute flags; a store whose
/// information cannot be read is silently skipped for the attribute check (its
/// presence is still reported).
#[must_use]
pub fn audit<R: Read + Seek>(vol: &mut VssVolume<R>) -> Vec<Anomaly> {
    let _ = vol;
    unimplemented!("RED: audit")
}

/// Audit a VSS volume and map each anomaly to a canonical [`Finding`], tagged
/// with the producing [`Source`] (`scope` names the evidence, e.g. the volume).
pub fn audit_findings<R: Read + Seek>(
    vol: &mut VssVolume<R>,
    scope: impl Into<String>,
) -> Vec<Finding> {
    let _ = (vol, scope.into());
    unimplemented!("RED: audit_findings")
}
