//! Synthetic (Tier-3) unit fixtures for the VSS reader.
//!
//! These build a minimal valid VSS byte image in-code and assert the parser
//! round-trips known values. They prove parser MECHANICS only — the authoritative
//! correctness check is the Tier-1 env-gated oracle test in
//! `tests/oracle_pcmus001.rs`, which validates against `pyvshadow` on a real
//! disk image.

use std::io::Cursor;

use crate::block::{BlockDescriptor, BlockDescriptorFlags, StoreBlockRange};
use crate::bytes::utf16le_string;
use crate::catalog::{
    catalog_next_block_offset, is_catalog_block, parse_catalog_entry, CatalogEntry, VolumeHeader,
    BLOCK_SIZE, CATALOG_ENTRY_LEN,
};
use crate::guid::{format_guid, VSS_IDENTIFIER};
use crate::store::{AttributeFlags, StoreBlockHeader, StoreInfo};
use crate::{VssError, VssVolume};

// ---------------------------------------------------------------------------
// Known synthetic values (Tier-3: we author both fixture and expected answer).
// ---------------------------------------------------------------------------

/// On-disk (mixed-endian) bytes of GUID `11223344-5566-7788-99aa-bbccddeeff00`.
const STORE_ID: [u8; 16] = [
    0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const STORE_ID_STR: &str = "11223344-5566-7788-99aa-bbccddeeff00";

/// On-disk bytes of GUID `aaaabbbb-cccc-dddd-eeee-ffff00001111`.
const SHADOW_ID: [u8; 16] = [
    0xbb, 0xbb, 0xaa, 0xaa, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xff, 0xff, 0x00, 0x00, 0x11, 0x11,
];
const SHADOW_ID_STR: &str = "aaaabbbb-cccc-dddd-eeee-ffff00001111";

/// On-disk bytes of GUID `22223333-4444-5555-6666-777788889999`.
const SET_ID: [u8; 16] = [
    0x33, 0x33, 0x22, 0x22, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99,
];
const SET_ID_STR: &str = "22223333-4444-5555-6666-777788889999";

const VOL_SIZE: u64 = 255_136_931_328;
const SEQ: u64 = 1;
const FLAGS: u64 = 0x40;
const CTIME: u64 = 130_000_000_000_000_000;
const CTX: u32 = 0x0000_0001;
const ATTR: u32 =
    AttributeFlags::PERSISTENT | AttributeFlags::CLIENT_ACCESSIBLE | AttributeFlags::DIFFERENTIAL;

const CATALOG_OFF: u64 = 0x4000;
const STORE_HDR_OFF: u64 = 0x8000;
const STORE_INFO_SIZE: u64 = 300;
const IMG_LEN: usize = 0x10000;
const OP_MACHINE: &str = "HOST-A";
const SVC_MACHINE: &str = "SVC-B";

fn wr(buf: &mut [u8], off: usize, data: &[u8]) {
    buf[off..off + data.len()].copy_from_slice(data);
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Build a minimal valid VSS volume image. `with_type3` controls whether the
/// snapshot's type-0x03 store pointer (and its store block/info) are present.
fn build_image(with_type3: bool) -> Vec<u8> {
    let mut b = vec![0u8; IMG_LEN];

    // Volume header @ 0x1E00.
    wr(&mut b, 0x1E00, &VSS_IDENTIFIER);
    wr(&mut b, 0x1E00 + 16, &1u32.to_le_bytes());
    wr(&mut b, 0x1E00 + 20, &1u32.to_le_bytes());
    wr(&mut b, 0x1E00 + 24, &0x1E00u64.to_le_bytes());
    wr(&mut b, 0x1E00 + 48, &CATALOG_OFF.to_le_bytes());

    // Catalog block @ CATALOG_OFF.
    let c = CATALOG_OFF as usize;
    wr(&mut b, c, &VSS_IDENTIFIER);
    wr(&mut b, c + 16, &1u32.to_le_bytes());
    wr(&mut b, c + 20, &2u32.to_le_bytes());
    wr(&mut b, c + 40, &0u64.to_le_bytes()); // next block offset = 0 (last)

    // Catalog entry 0: type 0x02 snapshot descriptor.
    let e0 = c + 128;
    wr(&mut b, e0, &2u64.to_le_bytes());
    wr(&mut b, e0 + 8, &VOL_SIZE.to_le_bytes());
    wr(&mut b, e0 + 16, &STORE_ID);
    wr(&mut b, e0 + 32, &SEQ.to_le_bytes());
    wr(&mut b, e0 + 40, &FLAGS.to_le_bytes());
    wr(&mut b, e0 + 48, &CTIME.to_le_bytes());

    if with_type3 {
        // Catalog entry 1: type 0x03 store pointer.
        let e1 = e0 + 128;
        wr(&mut b, e1, &3u64.to_le_bytes());
        wr(&mut b, e1 + 16, &STORE_ID);
        wr(&mut b, e1 + 32, &STORE_HDR_OFF.to_le_bytes());

        // Store block header @ STORE_HDR_OFF.
        let s = STORE_HDR_OFF as usize;
        wr(&mut b, s, &VSS_IDENTIFIER);
        wr(&mut b, s + 16, &1u32.to_le_bytes());
        wr(&mut b, s + 20, &4u32.to_le_bytes());
        wr(&mut b, s + 48, &STORE_INFO_SIZE.to_le_bytes());

        // Store information @ store header + 128.
        let si = s + 128;
        wr(&mut b, si + 16, &SHADOW_ID);
        wr(&mut b, si + 32, &SET_ID);
        wr(&mut b, si + 48, &CTX.to_le_bytes());
        wr(&mut b, si + 56, &ATTR.to_le_bytes());
        let op = utf16le(OP_MACHINE);
        wr(&mut b, si + 64, &(op.len() as u16).to_le_bytes());
        wr(&mut b, si + 66, &op);
        let svc_off = si + 66 + op.len();
        let svc = utf16le(SVC_MACHINE);
        wr(&mut b, svc_off, &(svc.len() as u16).to_le_bytes());
        wr(&mut b, svc_off + 2, &svc);
    }
    b
}

// ---------------------------------------------------------------------------
// GUID formatting
// ---------------------------------------------------------------------------

#[test]
fn format_guid_matches_vss_identifier() {
    // The canonical VSS GUID from the libvshadow spec — an authoritative check
    // that the mixed-endian rendering is correct.
    assert_eq!(
        format_guid(&VSS_IDENTIFIER),
        "3808876b-c176-4e48-b7ae-04046e6cc752"
    );
}

#[test]
fn format_guid_store_id() {
    assert_eq!(format_guid(&STORE_ID), STORE_ID_STR);
}

// ---------------------------------------------------------------------------
// Volume header
// ---------------------------------------------------------------------------

#[test]
fn volume_header_parse_valid() {
    let b = build_image(true);
    let vh = VolumeHeader::parse(&b[0x1E00..0x1E00 + 128]);
    assert!(vh.has_vss_identifier);
    assert_eq!(vh.version, 1);
    assert_eq!(vh.record_type, 1);
    assert_eq!(vh.current_offset, 0x1E00);
    assert_eq!(vh.catalog_offset, CATALOG_OFF);
}

#[test]
fn volume_header_no_identifier() {
    let vh = VolumeHeader::parse(&[0u8; 128]);
    assert!(!vh.has_vss_identifier);
    assert_eq!(vh.catalog_offset, 0);
}

// ---------------------------------------------------------------------------
// Catalog entries
// ---------------------------------------------------------------------------

#[test]
fn parse_catalog_entry_snapshot() {
    let b = build_image(true);
    let e0 = CATALOG_OFF as usize + 128;
    match parse_catalog_entry(&b[e0..e0 + CATALOG_ENTRY_LEN]) {
        CatalogEntry::Snapshot(d) => {
            assert_eq!(d.store_id, STORE_ID);
            assert_eq!(d.volume_size, VOL_SIZE);
            assert_eq!(d.sequence, SEQ);
            assert_eq!(d.flags, FLAGS);
            assert_eq!(d.creation_time, CTIME);
            assert_eq!(d.store_header_offset, None);
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

#[test]
fn parse_catalog_entry_store_pointer() {
    let b = build_image(true);
    let e1 = CATALOG_OFF as usize + 256;
    match parse_catalog_entry(&b[e1..e1 + CATALOG_ENTRY_LEN]) {
        CatalogEntry::StorePointer {
            store_id,
            store_header_offset,
        } => {
            assert_eq!(store_id, STORE_ID);
            assert_eq!(store_header_offset, STORE_HDR_OFF);
        }
        other => panic!("expected StorePointer, got {other:?}"),
    }
}

#[test]
fn parse_catalog_entry_empty_and_other() {
    assert_eq!(parse_catalog_entry(&[0u8; 128]), CatalogEntry::Empty);
    let mut other = [0u8; 128];
    other[0] = 0x01; // type 0x01
    assert_eq!(parse_catalog_entry(&other), CatalogEntry::Other);
}

#[test]
fn parse_catalog_entry_short_buffer_no_panic() {
    // Bounds-checked reads must yield an empty/zero entry, never panic.
    assert_eq!(parse_catalog_entry(&[]), CatalogEntry::Empty);
}

#[test]
fn catalog_helpers() {
    let b = build_image(true);
    let c = CATALOG_OFF as usize;
    assert!(is_catalog_block(&b[c..c + BLOCK_SIZE]));
    assert_eq!(catalog_next_block_offset(&b[c..c + BLOCK_SIZE]), 0);
    assert!(!is_catalog_block(&[0u8; BLOCK_SIZE]));
}

// ---------------------------------------------------------------------------
// Volume open / enumeration
// ---------------------------------------------------------------------------

#[test]
fn open_enumerates_single_store() {
    let mut vol = VssVolume::open(Cursor::new(build_image(true))).unwrap();
    assert!(vol.has_vss_header());
    assert_eq!(vol.store_count(), 1);
    assert_eq!(vol.catalog_offset(), CATALOG_OFF);
    assert_eq!(vol.volume_size(), IMG_LEN as u64);
    let d = &vol.stores()[0];
    assert_eq!(d.store_id_string(), STORE_ID_STR);
    assert_eq!(d.volume_size, VOL_SIZE);
    assert_eq!(d.sequence, SEQ);
    assert_eq!(d.flags, FLAGS);
    assert_eq!(d.creation_time, CTIME);
    assert_eq!(d.store_header_offset, Some(STORE_HDR_OFF));
}

#[test]
fn open_no_vss_header() {
    let mut vol = VssVolume::open(Cursor::new(vec![0u8; IMG_LEN])).unwrap();
    assert!(!vol.has_vss_header());
    assert_eq!(vol.store_count(), 0);
    assert!(vol.stores().is_empty());
}

#[test]
fn open_tiny_reader_no_header() {
    // A reader smaller than the header offset opens cleanly with no VSS.
    let mut vol = VssVolume::open(Cursor::new(vec![0u8; 100])).unwrap();
    assert!(!vol.has_vss_header());
    assert_eq!(vol.store_count(), 0);
}

#[test]
fn open_header_but_no_catalog() {
    let mut b = build_image(true);
    wr(&mut b, 0x1E00 + 48, &0u64.to_le_bytes()); // catalog offset = 0
    let vol = VssVolume::open(Cursor::new(b)).unwrap();
    assert!(vol.has_vss_header());
    assert_eq!(vol.store_count(), 0);
}

#[test]
fn open_corrupt_catalog_block_stops() {
    let mut b = build_image(true);
    let c = CATALOG_OFF as usize;
    wr(&mut b, c, &[0u8; 16]); // wipe the catalog block's VSS identifier
    let vol = VssVolume::open(Cursor::new(b)).unwrap();
    assert!(vol.has_vss_header());
    assert_eq!(vol.store_count(), 0);
}

#[test]
fn open_catalog_next_offset_out_of_range_stops() {
    let mut b = build_image(true);
    let c = CATALOG_OFF as usize;
    wr(&mut b, c + 40, &(IMG_LEN as u64).to_le_bytes()); // next block past end
    let vol = VssVolume::open(Cursor::new(b)).unwrap();
    assert_eq!(vol.store_count(), 1);
}

#[test]
fn open_catalog_self_loop_terminates() {
    let mut b = build_image(true);
    let c = CATALOG_OFF as usize;
    wr(&mut b, c + 40, &CATALOG_OFF.to_le_bytes()); // next block points at itself
    let vol = VssVolume::open(Cursor::new(b)).unwrap();
    // The visited-set guard stops the loop; the single store is still enumerated.
    assert_eq!(vol.store_count(), 1);
}

// ---------------------------------------------------------------------------
// Store information
// ---------------------------------------------------------------------------

#[test]
fn store_info_roundtrip() {
    let mut vol = VssVolume::open(Cursor::new(build_image(true))).unwrap();
    let info = vol.store_info(0).unwrap();
    assert_eq!(info.shadow_copy_id, SHADOW_ID);
    assert_eq!(info.shadow_copy_id_string(), SHADOW_ID_STR);
    assert_eq!(info.shadow_copy_set_id_string(), SET_ID_STR);
    assert_eq!(info.snapshot_context, CTX);
    assert_eq!(info.attributes.bits(), ATTR);
    assert!(info.attributes.is_persistent());
    assert!(info.attributes.is_client_accessible());
    assert!(info.attributes.is_differential());
    assert_eq!(info.operating_machine, OP_MACHINE);
    assert_eq!(info.service_machine, SVC_MACHINE);
}

#[test]
fn store_info_index_out_of_range() {
    let mut vol = VssVolume::open(Cursor::new(build_image(true))).unwrap();
    match vol.store_info(3) {
        Err(VssError::StoreIndexOutOfRange { index, count }) => {
            assert_eq!(index, 3);
            assert_eq!(count, 1);
        }
        other => panic!("expected StoreIndexOutOfRange, got {other:?}"),
    }
}

#[test]
fn store_info_unavailable_without_type3() {
    let mut vol = VssVolume::open(Cursor::new(build_image(false))).unwrap();
    assert_eq!(vol.store_count(), 1);
    assert!(vol.stores()[0].store_header_offset.is_none());
    match vol.store_info(0) {
        Err(VssError::StoreInfoUnavailable { index }) => assert_eq!(index, 0),
        other => panic!("expected StoreInfoUnavailable, got {other:?}"),
    }
}

#[test]
fn store_info_offset_out_of_bounds() {
    let mut b = build_image(true);
    let e1 = CATALOG_OFF as usize + 256;
    wr(&mut b, e1 + 32, &(IMG_LEN as u64 + 0x100000).to_le_bytes());
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    match vol.store_info(0) {
        Err(VssError::StoreOffsetOutOfBounds { index, offset, .. }) => {
            assert_eq!(index, 0);
            assert_eq!(offset, IMG_LEN as u64 + 0x100000);
        }
        other => panic!("expected StoreOffsetOutOfBounds, got {other:?}"),
    }
}

#[test]
fn store_info_offset_overflow() {
    let mut b = build_image(true);
    let e1 = CATALOG_OFF as usize + 256;
    wr(&mut b, e1 + 32, &u64::MAX.to_le_bytes());
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    assert!(matches!(
        vol.store_info(0),
        Err(VssError::StoreOffsetOutOfBounds { .. })
    ));
}

// ---------------------------------------------------------------------------
// Store block header + attribute flags
// ---------------------------------------------------------------------------

#[test]
fn store_block_header_parse() {
    let b = build_image(true);
    let s = STORE_HDR_OFF as usize;
    let sh = StoreBlockHeader::parse(&b[s..s + 128]);
    assert!(sh.has_vss_identifier);
    assert_eq!(sh.version, 1);
    assert_eq!(sh.record_type, 4);
    assert_eq!(sh.store_information_size, STORE_INFO_SIZE);
    assert_eq!(sh.next_offset, 0);
}

#[test]
fn attribute_flags_predicates() {
    let f = AttributeFlags(ATTR);
    assert_eq!(f.bits(), ATTR);
    assert!(f.is_persistent());
    assert!(f.is_client_accessible());
    assert!(f.is_differential());
    assert!(f.contains(AttributeFlags::PERSISTENT));
    let none = AttributeFlags(0);
    assert!(!none.is_persistent());
    assert!(!none.is_client_accessible());
    assert!(!none.is_differential());
    assert!(!none.contains(AttributeFlags::PERSISTENT));
}

#[test]
fn store_info_parse_short_buffer_no_panic() {
    let info = StoreInfo::parse(&[]);
    assert_eq!(info.operating_machine, "");
    assert_eq!(info.service_machine, "");
    assert_eq!(info.attributes.bits(), 0);
}

// ---------------------------------------------------------------------------
// Diff-area records (Phase-1 typed parsing only)
// ---------------------------------------------------------------------------

#[test]
fn block_descriptor_parse() {
    let mut buf = [0u8; 32];
    wr(&mut buf, 0, &0x1111_2222_3333_4444u64.to_le_bytes());
    wr(&mut buf, 8, &0x0000_0000_0000_5555u64.to_le_bytes());
    wr(&mut buf, 16, &0xaaaa_bbbb_cccc_ddddu64.to_le_bytes());
    wr(&mut buf, 24, &(BlockDescriptorFlags::OVERLAY).to_le_bytes());
    wr(&mut buf, 28, &0x89ab_cdefu32.to_le_bytes());
    let d = BlockDescriptor::parse(&buf);
    assert_eq!(d.original_offset, 0x1111_2222_3333_4444);
    assert_eq!(d.relative_store_offset, 0x5555);
    assert_eq!(d.store_offset, 0xaaaa_bbbb_cccc_dddd);
    assert!(d.flags.is_overlay());
    assert_eq!(d.allocation_bitmap, 0x89ab_cdef);
}

#[test]
fn block_descriptor_short_buffer_no_panic() {
    let d = BlockDescriptor::parse(&[]);
    assert_eq!(d.original_offset, 0);
    assert_eq!(d.allocation_bitmap, 0);
}

#[test]
fn block_descriptor_flags_predicates() {
    let f = BlockDescriptorFlags(BlockDescriptorFlags::FORWARDER | BlockDescriptorFlags::OVERLAY);
    assert_eq!(
        f.bits(),
        BlockDescriptorFlags::FORWARDER | BlockDescriptorFlags::OVERLAY
    );
    assert!(f.is_forwarder());
    assert!(f.is_overlay());
    assert!(!f.is_not_used());
    assert!(f.contains(BlockDescriptorFlags::FORWARDER));
    assert!(BlockDescriptorFlags(BlockDescriptorFlags::NOT_USED).is_not_used());
}

#[test]
fn store_block_range_parse() {
    let mut buf = [0u8; 24];
    wr(&mut buf, 0, &0x1000u64.to_le_bytes());
    wr(&mut buf, 8, &0x2000u64.to_le_bytes());
    wr(&mut buf, 16, &0x4000u64.to_le_bytes());
    let r = StoreBlockRange::parse(&buf);
    assert_eq!(r.store_offset, 0x1000);
    assert_eq!(r.relative_offset, 0x2000);
    assert_eq!(r.range_size, 0x4000);
    let empty = StoreBlockRange::parse(&[]);
    assert_eq!(empty.range_size, 0);
}

// ---------------------------------------------------------------------------
// UTF-16 decoding helper
// ---------------------------------------------------------------------------

#[test]
fn utf16le_string_handles_lone_surrogate_and_odd_byte() {
    // Lone high surrogate -> replacement char; trailing odd byte -> ignored.
    let bytes = [0x00, 0xd8, 0x41, 0x00, 0x42];
    assert_eq!(utf16le_string(&bytes), "\u{FFFD}A");
    assert_eq!(utf16le_string(&[]), "");
}
