//! Tier-1 oracle test: validate `vsc-core` against `pyvshadow` ground truth on a
//! real disk image (Magnet Virtual Summit 2023 CTF, `PC-MUS-001.E01`).
//!
//! This is the authoritative correctness check — an INDEPENDENT third-party
//! oracle (libvshadow/`pyvshadow`) on real-world data, not a fixture we authored.
//! It is env-gated: set `VSC_ORACLE_IMAGE` to the E01 path to run it, otherwise
//! it skips cleanly. See `tests/data/README.md` and `tests/oracle/vshadow_oracle.py`.
//!
//! Ground truth (confirmed 2026-07-08 via pyvshadow 20240504) — the main NTFS
//! volume (part 6, byte offset 122683392) carries exactly one shadow copy:
//!   store[0] id       = 1afc8871-8c76-11ed-8c4d-f894c2dfe804
//!            created  = 2023-01-04 21:38:00.8254268 UTC (raw FILETIME 133173418808254268;
//!                       pyvshadow prints the microsecond-truncated .825426)
//!            vol_size = 255136931328
//!
//! Run:
//! ```text
//! VSC_ORACLE_IMAGE=$HOME/src/issen/tests/data/magnet-summit-2023-ctf/PC-MUS-001.E01 \
//!   cargo test -p vsc-core --test oracle_pcmus001 -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Read, Seek, SeekFrom};

use ewf::EwfReader;
use vsc::VssVolume;

/// Byte offset of the main NTFS volume (part 6) within the CTF disk image — a
/// documented ground-truth constant (see tests/data/README.md).
const VOLUME_OFFSET: u64 = 122_683_392;

// Expected ground truth from the oracle.
const EXPECTED_STORE_ID: &str = "1afc8871-8c76-11ed-8c4d-f894c2dfe804";
const EXPECTED_VOLUME_SIZE: u64 = 255_136_931_328;
// Raw on-disk FILETIME: 2023-01-04 21:38:00.8254268 UTC. pyvshadow displays this
// truncated to microseconds (.825426); the parser reads the full 100 ns value.
const EXPECTED_FILETIME: u64 = 133_173_418_808_254_268;

/// A `Read + Seek` window that re-bases position 0 onto `base` of the inner
/// reader — presenting the NTFS volume as if it started at offset 0, which is
/// what [`VssVolume::open`] expects.
struct VolumeWindow<R> {
    inner: R,
    base: u64,
    pos: u64,
}

impl<R: Read + Seek> Read for VolumeWindow<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.seek(SeekFrom::Start(self.base + self.pos))?;
        let n = self.inner.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for VolumeWindow<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let inner_end = self.inner.seek(SeekFrom::End(0))?;
        let volume_len = inner_end.saturating_sub(self.base);
        self.pos = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::Current(o) => self.pos.saturating_add_signed(o),
            SeekFrom::End(o) => volume_len.saturating_add_signed(o),
        };
        Ok(self.pos)
    }
}

#[test]
fn pcmus001_matches_pyvshadow_oracle() {
    let Ok(path) = std::env::var("VSC_ORACLE_IMAGE") else {
        eprintln!("VSC_ORACLE_IMAGE unset — skipping Tier-1 oracle test");
        return;
    };
    if !std::path::Path::new(&path).exists() {
        eprintln!("VSC_ORACLE_IMAGE={path} not found — skipping Tier-1 oracle test");
        return;
    }

    let reader = EwfReader::open(&path).expect("open E01");
    let window = VolumeWindow {
        inner: reader,
        base: VOLUME_OFFSET,
        pos: 0,
    };
    let mut vol = VssVolume::open(window).expect("open VSS volume");

    eprintln!("has_vss_header = {}", vol.has_vss_header());
    eprintln!("store_count    = {}", vol.store_count());
    for (i, d) in vol.stores().iter().enumerate() {
        eprintln!(
            "store[{i}] id={} volume_size={} creation_time(FILETIME)={}",
            d.store_id_string(),
            d.volume_size,
            d.creation_time
        );
    }

    assert!(vol.has_vss_header(), "expected a VSS volume header");
    assert_eq!(vol.store_count(), 1, "expected exactly one shadow copy");

    let store = &vol.stores()[0];
    assert_eq!(store.store_id_string(), EXPECTED_STORE_ID, "store GUID");
    assert_eq!(
        store.volume_size, EXPECTED_VOLUME_SIZE,
        "shadow volume size"
    );
    assert_eq!(
        store.creation_time, EXPECTED_FILETIME,
        "creation time (raw FILETIME for 2023-01-04 21:38:00.825426 UTC)"
    );

    // Store information should be reachable (the store has a type-0x03 pointer).
    let info = vol.store_info(0).expect("read store information");
    eprintln!(
        "store_info: shadow_copy_id={} set_id={} attributes=0x{:08x} op_machine={:?}",
        info.shadow_copy_id_string(),
        info.shadow_copy_set_id_string(),
        info.attributes.bits(),
        info.operating_machine,
    );
}
