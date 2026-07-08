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
const STORE_BITMAP_OFF: u64 = 0xC000;
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
        wr(&mut b, e1 + 48, &STORE_BITMAP_OFF.to_le_bytes());

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
            store_bitmap_offset,
        } => {
            assert_eq!(store_id, STORE_ID);
            assert_eq!(store_header_offset, STORE_HDR_OFF);
            assert_eq!(store_bitmap_offset, STORE_BITMAP_OFF);
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
    let vol = VssVolume::open(Cursor::new(build_image(true))).unwrap();
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
    assert_eq!(d.store_bitmap_offset, Some(STORE_BITMAP_OFF));
}

#[test]
fn open_no_vss_header() {
    let vol = VssVolume::open(Cursor::new(vec![0u8; IMG_LEN])).unwrap();
    assert!(!vol.has_vss_header());
    assert_eq!(vol.store_count(), 0);
    assert!(vol.stores().is_empty());
}

#[test]
fn open_tiny_reader_no_header() {
    // A reader smaller than the header offset opens cleanly with no VSS.
    let vol = VssVolume::open(Cursor::new(vec![0u8; 100])).unwrap();
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
    wr(
        &mut b,
        e1 + 32,
        &(IMG_LEN as u64 + 0x0010_0000).to_le_bytes(),
    );
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    match vol.store_info(0) {
        Err(VssError::StoreOffsetOutOfBounds { index, offset, .. }) => {
            assert_eq!(index, 0);
            assert_eq!(offset, IMG_LEN as u64 + 0x0010_0000);
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

// ===========================================================================
// Phase-2 copy-on-write reconstruction (Tier-3 synthetic mechanics).
//
// These build a minimal in-memory VSS image whose diff area exercises every
// reconstruction path and assert `snapshot(0).read_block`/`read_at` produce the
// exact expected bytes. They prove mechanics only; the authoritative check is
// the Tier-1 env-gated oracle in `tests/reconstruct_pcmus001.rs` (pyvshadow on
// the real PC-MUS-001.E01 image).
// ===========================================================================

const RBS: usize = BLOCK_SIZE; // 16384
const R_IMG_LEN: usize = 16 * RBS; // 0x40000
const R_CATALOG: u64 = 0x4000; // block 1
const R_STORE_HDR: u64 = 0x1_0000; // block 4
const R_BITMAP1: u64 = 0x1_8000; // block 6
const R_BITMAP2: u64 = 0x3_C000; // block 15
const R_STORE7: u64 = 0x1_C000; // block 7, fill 0x77
const R_STORE8: u64 = 0x2_0000; // block 8, fill 0x88
const R_STORE9: u64 = 0x2_4000; // block 9, fill 0x99
const R_BLK2: u64 = 0x0_8000; // block 2, live fill 0x22 (passthrough)
const R_BLK3: u64 = 0x0_C000; // block 3, live fill 0x33 (bitmap-zeroed)
const R_BLK10: u64 = 0x2_8000; // plain-COW original
const R_BLK11: u64 = 0x2_C000; // overlay original
const R_BLK12: u64 = 0x3_0000; // overlay-only live base, fill 0xCC
const R_BLK13: u64 = 0x3_4000; // plain with out-of-range store offset
const R_BLK14: u64 = 0x3_8000; // plain + out-of-range overlay
const BAD_OFF: u64 = 0xFFFF_0000; // past the 0x40000-byte image

fn store_block_hdr(b: &mut [u8], off: u64, record_type: u32, relative: u64, next: u64) {
    let o = off as usize;
    wr(b, o, &VSS_IDENTIFIER);
    wr(b, o + 16, &1u32.to_le_bytes());
    wr(b, o + 20, &record_type.to_le_bytes());
    wr(b, o + 24, &relative.to_le_bytes());
    wr(b, o + 32, &off.to_le_bytes());
    wr(b, o + 40, &next.to_le_bytes());
}

fn desc(b: &mut [u8], off: usize, orig: u64, store_off: u64, flags: u32, alloc: u32) {
    wr(b, off, &orig.to_le_bytes());
    wr(b, off + 8, &0u64.to_le_bytes());
    wr(b, off + 16, &store_off.to_le_bytes());
    wr(b, off + 24, &flags.to_le_bytes());
    wr(b, off + 28, &alloc.to_le_bytes());
}

/// Build a VSS image whose store-0 diff area covers every reconstruction path.
fn build_reconstruct_image() -> Vec<u8> {
    let mut b = vec![0u8; R_IMG_LEN];

    // Volume header @ 0x1E00 -> catalog at R_CATALOG.
    wr(&mut b, 0x1E00, &VSS_IDENTIFIER);
    wr(&mut b, 0x1E00 + 16, &1u32.to_le_bytes());
    wr(&mut b, 0x1E00 + 20, &1u32.to_le_bytes());
    wr(&mut b, 0x1E00 + 24, &0x1E00u64.to_le_bytes());
    wr(&mut b, 0x1E00 + 48, &R_CATALOG.to_le_bytes());

    // Catalog block: snapshot entry + store pointer (header + bitmap offsets).
    let c = R_CATALOG as usize;
    wr(&mut b, c, &VSS_IDENTIFIER);
    wr(&mut b, c + 16, &1u32.to_le_bytes());
    wr(&mut b, c + 20, &2u32.to_le_bytes());
    let e0 = c + 128;
    wr(&mut b, e0, &2u64.to_le_bytes());
    wr(&mut b, e0 + 8, &(R_IMG_LEN as u64).to_le_bytes());
    wr(&mut b, e0 + 16, &STORE_ID);
    let e1 = e0 + 128;
    wr(&mut b, e1, &3u64.to_le_bytes());
    wr(&mut b, e1 + 16, &STORE_ID);
    wr(&mut b, e1 + 32, &R_STORE_HDR.to_le_bytes());
    wr(&mut b, e1 + 48, &R_BITMAP1.to_le_bytes());

    // Store header block (0x0004) — its content is irrelevant to reconstruction,
    // which reads the descriptor list at store_header + BLOCK_SIZE directly.
    store_block_hdr(&mut b, R_STORE_HDR, 4, 0, 0);

    // Block-descriptor list (0x0003) @ store_header + BLOCK_SIZE.
    let dl = R_STORE_HDR + RBS as u64;
    store_block_hdr(&mut b, dl, 3, 0, 0);
    let mut d = dl as usize + 128;
    // plain-COW: block10 <- store7 (0x77)
    desc(&mut b, d, R_BLK10, R_STORE7, 0, 0);
    d += 32;
    // overlay: block11 base <- store8 (0x88), overlaid sub 0+2 from store9 (0x99)
    desc(&mut b, d, R_BLK11, R_STORE8, 0, 0);
    d += 32;
    desc(
        &mut b,
        d,
        R_BLK11,
        R_STORE9,
        BlockDescriptorFlags::OVERLAY,
        0b101,
    );
    d += 32;
    // overlay-only: block12 base = live (0xCC), overlaid sub 0 from store9 (0x99)
    desc(
        &mut b,
        d,
        R_BLK12,
        R_STORE9,
        BlockDescriptorFlags::OVERLAY,
        0b001,
    );
    d += 32;
    // plain with out-of-range store offset -> zeroed base, no overlay
    desc(&mut b, d, R_BLK13, BAD_OFF, 0, 0);
    d += 32;
    // plain (store7 0x77) + overlay with out-of-range store offset -> overlay skipped
    desc(&mut b, d, R_BLK14, R_STORE7, 0, 0);
    d += 32;
    desc(
        &mut b,
        d,
        R_BLK14,
        BAD_OFF,
        BlockDescriptorFlags::OVERLAY,
        0b001,
    );
    d += 32;
    // not-used descriptor on block10 -> ignored (block10 stays 0x77)
    desc(
        &mut b,
        d,
        R_BLK10,
        R_STORE9,
        BlockDescriptorFlags::NOT_USED,
        0xFFFF_FFFF,
    );
    d += 32;
    // overlay+not-used on block12 -> excluded from overlays (block12 sub0 stays 0x99)
    desc(
        &mut b,
        d,
        R_BLK12,
        R_STORE8,
        BlockDescriptorFlags::OVERLAY | BlockDescriptorFlags::NOT_USED,
        0xFFFF_FFFF,
    );
    // (next 32 bytes are already zero -> terminator)

    // Store bitmap: chain of two 0x0006 blocks. bit 3 set -> block 3 unallocated.
    store_block_hdr(&mut b, R_BITMAP1, 6, 0, R_BITMAP2);
    b[R_BITMAP1 as usize + 128] = 0x08; // block number 3 -> byte 0 bit 3
    store_block_hdr(&mut b, R_BITMAP2, 6, (RBS - 128) as u64, 0);

    // Live/store data fills.
    fill(&mut b, R_BLK2, 0x22);
    fill(&mut b, R_BLK3, 0x33);
    fill(&mut b, R_BLK12, 0xCC);
    fill(&mut b, R_STORE7, 0x77);
    fill(&mut b, R_STORE8, 0x88);
    fill(&mut b, R_STORE9, 0x99);
    b
}

fn fill(b: &mut [u8], off: u64, byte: u8) {
    let o = off as usize;
    for x in &mut b[o..o + RBS] {
        *x = byte;
    }
}

#[test]
fn reconstruct_passthrough_block() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    assert_eq!(snap.read_block(R_BLK2).unwrap(), [0x22u8; RBS]);
}

#[test]
fn reconstruct_zero_fill_block() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // Live bytes are 0x33 but the bitmap marks block 3 unallocated -> zeros.
    assert_eq!(snap.read_block(R_BLK3).unwrap(), [0x00u8; RBS]);
}

#[test]
fn reconstruct_plain_cow_block() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // A not-used descriptor on the same block must be ignored.
    assert_eq!(snap.read_block(R_BLK10).unwrap(), [0x77u8; RBS]);
}

#[test]
fn reconstruct_overlay_block() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    let out = snap.read_block(R_BLK11).unwrap();
    let mut expected = [0x88u8; RBS];
    expected[0..512].fill(0x99); // sub-block 0
    expected[1024..1536].fill(0x99); // sub-block 2
    assert_eq!(out, expected);
}

#[test]
fn reconstruct_overlay_only_live_base() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    let out = snap.read_block(R_BLK12).unwrap();
    let mut expected = [0xCCu8; RBS]; // live base
    expected[0..512].fill(0x99); // overlay sub-block 0; not-used overlay ignored
    assert_eq!(out, expected);
}

#[test]
fn reconstruct_plain_out_of_range_store_offset_zeroed() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    assert_eq!(snap.read_block(R_BLK13).unwrap(), [0x00u8; RBS]);
}

#[test]
fn reconstruct_overlay_out_of_range_store_offset_skipped() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // Base plain is store7 (0x77); the bad overlay is skipped, not applied.
    assert_eq!(snap.read_block(R_BLK14).unwrap(), [0x77u8; RBS]);
}

#[test]
fn reconstruct_read_at_spans_block_boundary() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // Straddle block 2 (0x22 passthrough) and block 3 (bitmap zero-fill).
    let mut buf = [0xEEu8; 1024];
    snap.read_at(R_BLK3 - 512, &mut buf).unwrap();
    let mut expected = [0u8; 1024];
    expected[0..512].fill(0x22);
    assert_eq!(buf, expected);
}

#[test]
fn reconstruct_read_at_past_volume_end_is_zero() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    let mut buf = [0xEEu8; RBS];
    snap.read_at(R_IMG_LEN as u64, &mut buf).unwrap();
    assert_eq!(buf, [0u8; RBS]);
}

#[test]
fn reconstruct_read_block_unaligned_offset_aligns_down() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // An offset inside block 2 reconstructs the whole aligned block.
    assert_eq!(snap.read_block(R_BLK2 + 777).unwrap(), [0x22u8; RBS]);
}

#[test]
fn snapshot_index_out_of_range() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    match vol.snapshot(5) {
        Err(VssError::StoreIndexOutOfRange { index, count }) => {
            assert_eq!(index, 5);
            assert_eq!(count, 1);
        }
        other => panic!("expected StoreIndexOutOfRange, got {other:?}"),
    }
}

#[test]
fn snapshot_unavailable_without_type3() {
    // build_image(false) has a snapshot entry but no type-0x03 store pointer.
    let mut vol = VssVolume::open(Cursor::new(build_image(false))).unwrap();
    match vol.snapshot(0) {
        Err(VssError::StoreInfoUnavailable { index }) => assert_eq!(index, 0),
        other => panic!("expected StoreInfoUnavailable, got {other:?}"),
    }
}

#[test]
fn reconstruct_descriptor_list_wrong_record_type_yields_no_descriptors() {
    let mut b = build_reconstruct_image();
    let dl = (R_STORE_HDR + RBS as u64) as usize;
    wr(&mut b, dl + 20, &5u32.to_le_bytes()); // not 0x0003
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // No descriptors -> block 10 falls through to live passthrough (unfilled = 0).
    assert_eq!(snap.read_block(R_BLK10).unwrap(), [0x00u8; RBS]);
}

#[test]
fn reconstruct_descriptor_list_cycle_terminates() {
    let mut b = build_reconstruct_image();
    let dl = R_STORE_HDR + RBS as u64;
    wr(&mut b, dl as usize + 40, &dl.to_le_bytes()); // next -> itself
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    assert_eq!(snap.read_block(R_BLK10).unwrap(), [0x77u8; RBS]);
}

#[test]
fn reconstruct_descriptor_list_next_out_of_range_stops() {
    let mut b = build_reconstruct_image();
    let dl = R_STORE_HDR + RBS as u64;
    wr(&mut b, dl as usize + 40, &(R_IMG_LEN as u64).to_le_bytes()); // next past end
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    assert_eq!(snap.read_block(R_BLK10).unwrap(), [0x77u8; RBS]);
}

#[test]
fn reconstruct_bitmap_wrong_record_type_disables_zero_fill() {
    let mut b = build_reconstruct_image();
    wr(&mut b, R_BITMAP1 as usize + 20, &5u32.to_le_bytes()); // not 0x0006
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    // Empty bitmap -> block 3 is no longer unallocated -> live passthrough (0x33).
    assert_eq!(snap.read_block(R_BLK3).unwrap(), [0x33u8; RBS]);
}

#[test]
fn reconstruct_bitmap_cycle_terminates() {
    let mut b = build_reconstruct_image();
    wr(&mut b, R_BITMAP1 as usize + 40, &R_BITMAP1.to_le_bytes()); // next -> itself
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    assert_eq!(snap.read_block(R_BLK3).unwrap(), [0x00u8; RBS]);
}

#[test]
fn reconstruct_bitmap_next_out_of_range_stops() {
    let mut b = build_reconstruct_image();
    wr(
        &mut b,
        R_BITMAP1 as usize + 40,
        &(R_IMG_LEN as u64).to_le_bytes(),
    ); // next past end
    let mut vol = VssVolume::open(Cursor::new(b)).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    assert_eq!(snap.read_block(R_BLK3).unwrap(), [0x00u8; RBS]);
}

#[test]
fn reconstruct_read_at_empty_buffer_is_ok() {
    let mut vol = VssVolume::open(Cursor::new(build_reconstruct_image())).unwrap();
    let mut snap = vol.snapshot(0).unwrap();
    let mut buf = [0u8; 0];
    snap.read_at(0, &mut buf).unwrap();
}
