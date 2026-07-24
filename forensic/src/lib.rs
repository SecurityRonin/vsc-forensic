//! # vsc-forensic — Volume Shadow Copy anomaly auditor
//!
//! Walks the shadow-copy stores decoded by [`vsc`] and emits severity-graded
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
        match self {
            AnomalyKind::StorePresent { .. } => Severity::Info,
            AnomalyKind::NoShadowCopies | AnomalyKind::StoreNonPersistent { .. } => Severity::Low,
            AnomalyKind::SequenceGap { .. } => Severity::Medium,
        }
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::NoShadowCopies => "VSC-NO-SHADOW-COPIES",
            AnomalyKind::StorePresent { .. } => "VSC-STORE-PRESENT",
            AnomalyKind::SequenceGap { .. } => "VSC-SEQUENCE-GAP",
            AnomalyKind::StoreNonPersistent { .. } => "VSC-STORE-NON-PERSISTENT",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::NoShadowCopies | AnomalyKind::StorePresent { .. } => Category::History,
            AnomalyKind::SequenceGap { .. } => Category::Residue,
            AnomalyKind::StoreNonPersistent { .. } => Category::Provenance,
        }
    }

    /// Human-readable, "consistent with" note including the offending values.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::NoShadowCopies => {
                "the volume carries a VSS volume header but the catalog \
                 enumerated zero shadow-copy stores; consistent with shadow-copy deletion (MITRE \
                 T1490) or a volume that never had snapshots — not a determination of deletion"
                    .to_string()
            }
            AnomalyKind::StorePresent {
                store_id,
                sequence,
                volume_size,
                ..
            } => format!(
                "shadow copy {store_id} is present (catalog sequence {sequence}, shadow volume \
                 size {volume_size} bytes)"
            ),
            AnomalyKind::SequenceGap { previous, next } => format!(
                "catalog sequence numbers are non-contiguous ({previous} -> {next}); consistent \
                 with a deleted intermediate shadow copy"
            ),
            AnomalyKind::StoreNonPersistent {
                store_id,
                attribute_flags,
            } => format!(
                "shadow copy {store_id} attribute flags 0x{attribute_flags:08x} lack the \
                 persistent bit; a non-persistent shadow copy does not survive a reboot"
            ),
        }
    }

    /// MITRE ATT&CK technique ids this kind is consistent with.
    #[must_use]
    pub fn mitre(&self) -> &'static [&'static str] {
        match self {
            AnomalyKind::NoShadowCopies | AnomalyKind::SequenceGap { .. } => &["T1490"],
            AnomalyKind::StorePresent { .. } | AnomalyKind::StoreNonPersistent { .. } => &[],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        match self {
            AnomalyKind::StorePresent { store_id, .. }
            | AnomalyKind::StoreNonPersistent { store_id, .. } => vec![SubjectRef {
                scheme: "vss".to_string(),
                kind: "shadow_copy".to_string(),
                id: store_id.clone(),
                label: None,
            }],
            AnomalyKind::NoShadowCopies | AnomalyKind::SequenceGap { .. } => Vec::new(),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::NoShadowCopies => Vec::new(),
            AnomalyKind::StorePresent {
                store_id,
                sequence,
                volume_size,
                creation_time,
            } => vec![
                evidence("store_id", store_id.clone()),
                evidence("sequence", sequence.to_string()),
                evidence("volume_size", volume_size.to_string()),
                evidence("creation_time_filetime", creation_time.to_string()),
            ],
            AnomalyKind::SequenceGap { previous, next } => vec![
                evidence("previous_sequence", previous.to_string()),
                evidence("next_sequence", next.to_string()),
            ],
            AnomalyKind::StoreNonPersistent {
                store_id,
                attribute_flags,
            } => vec![
                evidence("store_id", store_id.clone()),
                evidence("attribute_flags", format!("0x{attribute_flags:08x}")),
            ],
        }
    }

    fn timestamps(&self) -> Vec<Timestamp> {
        match self {
            AnomalyKind::StorePresent { creation_time, .. } => filetime_to_rfc3339(*creation_time)
                .map(|value| {
                    vec![Timestamp {
                        value,
                        kind: "created".to_string(),
                        location: None,
                    }]
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

fn evidence(field: &str, value: String) -> Evidence {
    Evidence {
        field: field.to_string(),
        value,
        location: None,
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
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }

    /// Assemble the canonical [`Finding`], adding the FILETIME-derived timestamps
    /// the [`Observation`] trait cannot carry on its own.
    #[must_use]
    pub fn to_finding(&self, source: Source) -> Finding {
        let mut finding = Observation::to_finding(self, source);
        for timestamp in self.kind.timestamps() {
            finding.context.timestamps.push(timestamp);
        }
        finding
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn subjects(&self) -> Vec<SubjectRef> {
        self.kind.subjects()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
    fn mitre(&self) -> &'static [&'static str] {
        self.kind.mitre()
    }
}

/// Convert a raw Windows FILETIME to an RFC 3339 string, or `None` when the value
/// is zero or predates the Unix epoch.
#[must_use]
pub fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    if filetime == 0 || filetime < FILETIME_EPOCH_DIFF {
        return None;
    }
    let unix_nanos = i128::from(filetime - FILETIME_EPOCH_DIFF) * 100;
    jiff::Timestamp::from_nanosecond(unix_nanos)
        .ok()
        .map(|t| t.to_string())
}

/// Audit the shadow copies of a VSS volume, returning classified anomalies.
///
/// Reads each store's information to inspect attribute flags; a store whose
/// information cannot be read is silently skipped for the attribute check (its
/// presence is still reported).
#[must_use]
pub fn audit<R: Read + Seek>(vol: &mut VssVolume<R>) -> Vec<Anomaly> {
    let descriptors = vol.stores().to_vec();

    // A validated VSS header with an empty catalog is the one degrade-to-empty
    // that IS a finding — never silently "no results".
    if vol.has_vss_header() && descriptors.is_empty() {
        return vec![Anomaly::new(AnomalyKind::NoShadowCopies)];
    }

    let mut out = Vec::new();
    for descriptor in &descriptors {
        out.push(Anomaly::new(AnomalyKind::StorePresent {
            store_id: descriptor.store_id_string(),
            sequence: descriptor.sequence,
            volume_size: descriptor.volume_size,
            creation_time: descriptor.creation_time,
        }));
    }

    let mut sequences: Vec<u64> = descriptors.iter().map(|d| d.sequence).collect();
    sequences.sort_unstable();
    for (previous, next) in sequences
        .iter()
        .copied()
        .zip(sequences.iter().copied().skip(1))
    {
        if next > previous.saturating_add(1) {
            out.push(Anomaly::new(AnomalyKind::SequenceGap { previous, next }));
        }
    }

    for (index, descriptor) in descriptors.iter().enumerate() {
        if let Ok(info) = vol.store_info(index) {
            if !info.attributes.is_persistent() {
                out.push(Anomaly::new(AnomalyKind::StoreNonPersistent {
                    store_id: descriptor.store_id_string(),
                    attribute_flags: info.attributes.bits(),
                }));
            }
        }
    }

    out
}

/// Audit a VSS volume and map each anomaly to a canonical [`Finding`], tagged
/// with the producing [`Source`] (`scope` names the evidence, e.g. the volume).
pub fn audit_findings<R: Read + Seek>(
    vol: &mut VssVolume<R>,
    scope: impl Into<String>,
) -> Vec<Finding> {
    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    audit(vol)
        .into_iter()
        .map(|anomaly| anomaly.to_finding(source.clone()))
        .collect()
}
