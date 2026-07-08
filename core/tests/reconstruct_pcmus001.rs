//! Tier-1 reconstruction oracle: validate `vsc-core`'s copy-on-write snapshot
//! reconstruction against `pyvshadow` (libvshadow) ground truth on the real
//! Magnet Virtual Summit 2023 CTF image (`PC-MUS-001.E01`).
//!
//! This is the authoritative correctness check for Phase-2 — an INDEPENDENT
//! third-party oracle on real-world data, not a fixture we authored. For each
//! representative volume offset (passthrough / zero-fill / plain-COW / overlay),
//! it reconstructs the 16384-byte block and asserts its sha256 matches the value
//! libvshadow produces (captured in `tests/oracle/reconstruction_oracle.json`).
//!
//! Env-gated on `VSC_ORACLE_IMAGE`; skips cleanly when unset. Run:
//! ```text
//! VSC_ORACLE_IMAGE=$HOME/src/issen/tests/data/magnet-summit-2023-ctf/PC-MUS-001.E01 \
//!   cargo test -p vsc-core --test reconstruct_pcmus001 -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Read, Seek, SeekFrom};

use ewf::EwfReader;
use sha2::{Digest, Sha256};
use vsc::VssVolume;

/// Byte offset of the main NTFS volume (part 6) within the CTF disk image.
const VOLUME_OFFSET: u64 = 122_683_392;

const BLOCK_SIZE: usize = 16_384;

/// The Tier-1 oracle cases from `tests/oracle/reconstruction_oracle.json`
/// (pyvshadow 20240504, store 0). Each is `(volume_offset, kind, sha256-hex)`.
const CASES: &[(u64, &str, &str)] = &[
    (
        0,
        "passthrough",
        "abde4a4a90d2dd86ee17e4835456483e06aaa5381bae8b131b943d4f85cab6c6",
    ),
    (
        16_384,
        "passthrough",
        "3dc9ae56c5ea2eac8d9f4e47b9e31a873a29cb3c6e3b90ecf5adc4096d1250d4",
    ),
    (
        163_840,
        "zero-fill",
        "4fe7b59af6de3b665b67788cc2f99892ab827efae3a467342b3bb4e3bc8e5bfe",
    ),
    (
        3_997_696,
        "cow-plain",
        "da262d8fcf31c4db265671ba6851032c3cc1980bb79679f31e9dc94037201f65",
    ),
    (
        4_227_072,
        "overlay",
        "a1718f9d1db924d3adfb7c9f05f1cc498ef51b86dda1e719bd3ff7f98fc20d8e",
    ),
];

/// A `Read + Seek` window that re-bases position 0 onto `base` of the inner
/// reader — presenting the NTFS volume as if it started at offset 0.
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

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn pcmus001_reconstruction_matches_pyvshadow_oracle() {
    let Ok(path) = std::env::var("VSC_ORACLE_IMAGE") else {
        eprintln!("VSC_ORACLE_IMAGE unset — skipping Tier-1 reconstruction oracle test");
        return;
    };
    if !std::path::Path::new(&path).exists() {
        eprintln!("VSC_ORACLE_IMAGE={path} not found — skipping Tier-1 reconstruction oracle test");
        return;
    }

    let reader = EwfReader::open(&path).expect("open E01");
    let window = VolumeWindow {
        inner: reader,
        base: VOLUME_OFFSET,
        pos: 0,
    };
    let mut vol = VssVolume::open(window).expect("open VSS volume");
    assert_eq!(vol.store_count(), 1, "expected exactly one shadow copy");

    let mut snap = vol.snapshot(0).expect("build snapshot 0");

    let mut failures = 0;
    for &(offset, kind, want) in CASES {
        let block = snap.read_block(offset).expect("reconstruct block");
        assert_eq!(block.len(), BLOCK_SIZE);
        let got = hex(Sha256::digest(block).as_slice());
        let ok = got == want;
        eprintln!(
            "offset={offset:<9} kind={kind:<11} {} parsed={got} oracle={want}",
            if ok { "PASS" } else { "FAIL" }
        );
        if !ok {
            failures += 1;
        }
    }
    assert_eq!(
        failures, 0,
        "{failures} reconstructed block(s) mismatched the pyvshadow oracle"
    );
}
