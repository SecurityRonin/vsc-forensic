#![no_main]
//! Fuzz the full catalog path: open a VSS volume over arbitrary bytes, enumerate
//! its stores, and read each store's information. Invariant: must never panic.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use vsc::VssVolume;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut vol) = VssVolume::open(Cursor::new(data.to_vec())) {
        let _ = vol.has_vss_header();
        let _ = vol.catalog_offset();
        let _ = vol.volume_size();
        let count = vol.store_count();
        for i in 0..count {
            let _ = vol.store_info(i);
        }
        // One past the end must be a clean error, not a panic.
        let _ = vol.store_info(count);
    }
});
