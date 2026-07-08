#![no_main]
//! Fuzz the record parsers directly over arbitrary bytes: store information,
//! store block header, and the diff-area records. Invariant: must never panic.

use libfuzzer_sys::fuzz_target;
use vsc::{BlockDescriptor, StoreBlockHeader, StoreBlockRange, StoreInfo};

fuzz_target!(|data: &[u8]| {
    let info = StoreInfo::parse(data);
    let _ = info.shadow_copy_id_string();
    let _ = info.shadow_copy_set_id_string();
    let _ = info.attributes.is_persistent();

    let _ = StoreBlockHeader::parse(data);
    let _ = BlockDescriptor::parse(data);
    let _ = StoreBlockRange::parse(data);
});
