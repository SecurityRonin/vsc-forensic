#![no_main]
//! Fuzz the Phase-2 reconstruction path: open a VSS volume over arbitrary bytes,
//! build a snapshot of store 0, and reconstruct a few blocks / spanning reads.
//! Invariant: must never panic, never read out of bounds.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use vsc::VssVolume;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut vol) = VssVolume::open(Cursor::new(data.to_vec())) {
        if let Ok(mut snap) = vol.snapshot(0) {
            // Aligned, unaligned, and past-end block reconstructions.
            let _ = snap.read_block(0);
            let _ = snap.read_block(16_384 + 123);
            let _ = snap.read_block(u64::MAX);

            // Arbitrary spanning reads, including a boundary-straddling one.
            let mut buf = [0u8; 40_000];
            let _ = snap.read_at(0, &mut buf);
            let _ = snap.read_at(16_384 - 7, &mut buf[..64]);
            let _ = snap.read_at(u64::MAX - 10, &mut buf[..32]);
        }
    }
});
