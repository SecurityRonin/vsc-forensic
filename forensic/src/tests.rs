//! Unit tests for the VSS anomaly auditor (Tier-3 synthetic fixtures).
//!
//! Build minimal VSS volume images in-code and assert the graded findings the
//! auditor emits. Parser correctness itself is validated by vsc-core's Tier-1
//! oracle; these tests fix the auditor's classification and finding mapping.

use std::io::Cursor;

use forensicnomicon::report::{Category, Severity, Source};
use vsc::{AttributeFlags, VssVolume};

use crate::{audit, audit_findings, filetime_to_rfc3339, Anomaly, AnomalyKind, ANALYZER};

/// A real-store FILETIME (2023-01-04 21:38:00.8254268 UTC) reused for timestamp
/// assertions.
const CTIME: u64 = 133_173_418_808_254_268;

const CATALOG_OFF: u64 = 0x4000;
const STORE_BASE: u64 = 0x8000;
const STORE_STRIDE: u64 = 0x4000;
const STORE_INFO_SIZE: u64 = 300;

struct StoreSpec {
    store_id: [u8; 16],
    sequence: u64,
    volume_size: u64,
    creation_time: u64,
    attr: u32,
}

fn sid(tag: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0] = tag;
    g
}

fn spec(tag: u8, sequence: u64, attr: u32) -> StoreSpec {
    StoreSpec {
        store_id: sid(tag),
        sequence,
        volume_size: 1024 * 1024 * 1024,
        creation_time: CTIME,
        attr,
    }
}

fn wr(b: &mut [u8], off: usize, d: &[u8]) {
    b[off..off + d.len()].copy_from_slice(d);
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Build a VSS volume image. `header` writes the volume header at 0x1E00;
/// `catalog` names and populates the catalog with one entry pair per spec.
fn build(specs: &[StoreSpec], header: bool, catalog: bool) -> Vec<u8> {
    let n = specs.len().max(1) as u64;
    let img_len = (STORE_BASE + STORE_STRIDE * n + 0x1000) as usize;
    let mut b = vec![0u8; img_len];

    if header {
        wr(&mut b, 0x1E00, &vsc::VSS_IDENTIFIER);
        wr(&mut b, 0x1E00 + 16, &1u32.to_le_bytes());
        wr(&mut b, 0x1E00 + 20, &1u32.to_le_bytes());
        wr(&mut b, 0x1E00 + 24, &0x1E00u64.to_le_bytes());
        if catalog {
            wr(&mut b, 0x1E00 + 48, &CATALOG_OFF.to_le_bytes());
        }
    }

    if header && catalog {
        let c = CATALOG_OFF as usize;
        wr(&mut b, c, &vsc::VSS_IDENTIFIER);
        wr(&mut b, c + 16, &1u32.to_le_bytes());
        wr(&mut b, c + 20, &2u32.to_le_bytes());
        wr(&mut b, c + 40, &0u64.to_le_bytes());

        for (i, s) in specs.iter().enumerate() {
            let hoff = STORE_BASE + STORE_STRIDE * i as u64;
            let e02 = c + 128 + i * 256;
            wr(&mut b, e02, &2u64.to_le_bytes());
            wr(&mut b, e02 + 8, &s.volume_size.to_le_bytes());
            wr(&mut b, e02 + 16, &s.store_id);
            wr(&mut b, e02 + 32, &s.sequence.to_le_bytes());
            wr(&mut b, e02 + 40, &0x40u64.to_le_bytes());
            wr(&mut b, e02 + 48, &s.creation_time.to_le_bytes());

            let e03 = e02 + 128;
            wr(&mut b, e03, &3u64.to_le_bytes());
            wr(&mut b, e03 + 16, &s.store_id);
            wr(&mut b, e03 + 32, &hoff.to_le_bytes());

            let h = hoff as usize;
            wr(&mut b, h, &vsc::VSS_IDENTIFIER);
            wr(&mut b, h + 16, &1u32.to_le_bytes());
            wr(&mut b, h + 20, &4u32.to_le_bytes());
            wr(&mut b, h + 48, &STORE_INFO_SIZE.to_le_bytes());

            let si = h + 128;
            wr(&mut b, si + 16, &s.store_id);
            wr(&mut b, si + 32, &s.store_id);
            wr(&mut b, si + 48, &1u32.to_le_bytes());
            wr(&mut b, si + 56, &s.attr.to_le_bytes());
            let op = utf16le("HOST");
            wr(&mut b, si + 64, &(op.len() as u16).to_le_bytes());
            wr(&mut b, si + 66, &op);
        }
    }
    b
}

fn open(image: Vec<u8>) -> VssVolume<Cursor<Vec<u8>>> {
    VssVolume::open(Cursor::new(image)).unwrap()
}

const PERSISTENT_CA: u32 = AttributeFlags::PERSISTENT | AttributeFlags::CLIENT_ACCESSIBLE;

// ---------------------------------------------------------------------------

#[test]
fn audit_no_shadow_copies() {
    let mut vol = open(build(&[], true, false));
    let anomalies = audit(&mut vol);
    assert_eq!(anomalies.len(), 1);
    let a = &anomalies[0];
    assert_eq!(a.code, "VSC-NO-SHADOW-COPIES");
    assert_eq!(a.severity, Severity::Low);
    assert_eq!(a.kind, AnomalyKind::NoShadowCopies);
    assert_eq!(a.kind.category(), Category::History);
    assert_eq!(a.kind.mitre(), &["T1490"]);
    assert!(a.note.contains("consistent with"));
}

#[test]
fn audit_empty_without_vss_header() {
    let mut vol = open(build(&[], false, false));
    assert!(!vol.has_vss_header());
    assert!(audit(&mut vol).is_empty());
}

#[test]
fn audit_reports_store_present() {
    let mut vol = open(build(&[spec(1, 5, PERSISTENT_CA)], true, true));
    let anomalies = audit(&mut vol);
    let present: Vec<_> = anomalies
        .iter()
        .filter(|a| matches!(a.kind, AnomalyKind::StorePresent { .. }))
        .collect();
    assert_eq!(present.len(), 1);
    let a = present[0];
    assert_eq!(a.code, "VSC-STORE-PRESENT");
    assert_eq!(a.severity, Severity::Info);
    assert_eq!(a.kind.category(), Category::History);
    match &a.kind {
        AnomalyKind::StorePresent {
            store_id, sequence, ..
        } => {
            assert_eq!(store_id, &vsc::format_guid(&sid(1)));
            assert_eq!(*sequence, 5);
        }
        other => panic!("expected StorePresent, got {other:?}"),
    }
    // No gap and persistent -> only StorePresent is emitted.
    assert_eq!(anomalies.len(), 1);
}

#[test]
fn audit_detects_sequence_gap() {
    let mut vol = open(build(
        &[spec(1, 1, PERSISTENT_CA), spec(2, 3, PERSISTENT_CA)],
        true,
        true,
    ));
    let anomalies = audit(&mut vol);
    let gaps: Vec<_> = anomalies
        .iter()
        .filter_map(|a| match a.kind {
            AnomalyKind::SequenceGap { previous, next } => Some((previous, next)),
            _ => None,
        })
        .collect();
    assert_eq!(gaps, vec![(1, 3)]);
    let gap = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::SequenceGap { .. }))
        .unwrap();
    assert_eq!(gap.code, "VSC-SEQUENCE-GAP");
    assert_eq!(gap.severity, Severity::Medium);
    assert_eq!(gap.kind.category(), Category::Residue);
    assert_eq!(gap.kind.mitre(), &["T1490"]);
}

#[test]
fn audit_no_gap_when_contiguous() {
    let mut vol = open(build(
        &[spec(1, 1, PERSISTENT_CA), spec(2, 2, PERSISTENT_CA)],
        true,
        true,
    ));
    let anomalies = audit(&mut vol);
    assert!(!anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::SequenceGap { .. })));
}

#[test]
fn audit_flags_non_persistent_store() {
    let mut vol = open(build(
        &[spec(1, 1, AttributeFlags::CLIENT_ACCESSIBLE)],
        true,
        true,
    ));
    let anomalies = audit(&mut vol);
    let np = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::StoreNonPersistent { .. }))
        .expect("expected StoreNonPersistent");
    assert_eq!(np.code, "VSC-STORE-NON-PERSISTENT");
    assert_eq!(np.severity, Severity::Low);
    assert_eq!(np.kind.category(), Category::Provenance);
}

#[test]
fn audit_persistent_store_not_flagged() {
    let mut vol = open(build(&[spec(1, 1, PERSISTENT_CA)], true, true));
    let anomalies = audit(&mut vol);
    assert!(!anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::StoreNonPersistent { .. })));
}

#[test]
fn audit_findings_tags_source_and_timestamp() {
    let mut vol = open(build(&[spec(1, 1, PERSISTENT_CA)], true, true));
    let findings = audit_findings(&mut vol, "volume: test");
    assert!(!findings.is_empty());
    let f = &findings[0];
    assert_eq!(f.source.analyzer, ANALYZER);
    assert_eq!(f.source.scope, "volume: test");
    assert!(f.source.version.is_some());
    assert_eq!(f.severity, Some(Severity::Info));
    assert!(!f.subjects.is_empty());
    assert!(f
        .context
        .timestamps
        .iter()
        .any(|t| t.kind == "created" && t.value.starts_with("2023-01-04T21:38:00")));
}

#[test]
fn every_kind_converts_to_finding() {
    let kinds = [
        AnomalyKind::NoShadowCopies,
        AnomalyKind::StorePresent {
            store_id: vsc::format_guid(&sid(1)),
            sequence: 1,
            volume_size: 2048,
            creation_time: CTIME,
        },
        AnomalyKind::SequenceGap {
            previous: 1,
            next: 3,
        },
        AnomalyKind::StoreNonPersistent {
            store_id: vsc::format_guid(&sid(1)),
            attribute_flags: AttributeFlags::CLIENT_ACCESSIBLE,
        },
    ];
    for kind in kinds {
        let source = Source {
            analyzer: ANALYZER.to_string(),
            scope: "vol".to_string(),
            version: None,
        };
        let anomaly = Anomaly::new(kind);
        let finding = anomaly.to_finding(source);
        assert!(!finding.code.is_empty());
        assert!(!finding.note.is_empty());
        assert_eq!(finding.severity, Some(anomaly.severity));
    }
}

#[test]
fn no_shadow_copies_finding_carries_mitre() {
    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: "vol".to_string(),
        version: None,
    };
    let finding = Anomaly::new(AnomalyKind::NoShadowCopies).to_finding(source);
    assert_eq!(finding.severity, Some(Severity::Low));
    assert!(finding
        .context
        .external_refs
        .iter()
        .any(|r| r.id == "T1490"));
    assert!(finding.context.timestamps.is_empty());
}

#[test]
fn store_present_finding_has_subject_and_evidence() {
    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: "vol".to_string(),
        version: None,
    };
    let finding = Anomaly::new(AnomalyKind::StorePresent {
        store_id: vsc::format_guid(&sid(7)),
        sequence: 9,
        volume_size: 4096,
        creation_time: CTIME,
    })
    .to_finding(source);
    assert!(finding
        .subjects
        .iter()
        .any(|s| s.scheme == "vss" && s.kind == "shadow_copy"));
    assert!(finding.evidence.iter().any(|e| e.field == "sequence"));
}

#[test]
fn filetime_conversion() {
    let s = filetime_to_rfc3339(CTIME).unwrap();
    assert!(s.starts_with("2023-01-04T21:38:00"), "got {s}");
    assert!(filetime_to_rfc3339(0).is_none());
    assert!(filetime_to_rfc3339(1).is_none());
}
