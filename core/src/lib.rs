//! # vsc-core — Windows Volume Shadow Copy (VSS) reader
//!
//! A panic-free decoder for the on-disk structures of Windows Volume Shadow Copy
//! (VSS), the `[P^H]` disk-history substrate of the forensic fleet. Given a
//! positioned `Read + Seek` over an NTFS **volume** (offset 0 = the NTFS boot
//! sector), [`VssVolume::open`] reads the VSS volume header at byte offset
//! `0x1E00`, walks the catalog of shadow-copy stores, and exposes each store's
//! [`StoreInfo`] on demand.
//!
//! The reader stays pure: it decodes bytes into typed records and makes no
//! forensic judgments (those live in the sibling `vsc-forensic` analyzer). It
//! never loads the whole volume into memory — the real volumes are hundreds of
//! gigabytes — and every multi-byte read is bounds-checked, so malformed input
//! yields safe defaults or a typed [`VssError`], never a panic.
//!
//! Phase 1 (this crate) enumerates stores and decodes store information plus the
//! typed diff-area records ([`BlockDescriptor`], [`StoreBlockRange`]). The
//! copy-on-write block-reconstruction engine is Phase 2 and out of scope here.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{Read, Seek};

mod bytes;
pub mod block;
pub mod catalog;
pub mod error;
pub mod guid;
pub mod store;

#[cfg(test)]
mod tests;

pub use block::{BlockDescriptor, BlockDescriptorFlags, StoreBlockRange};
pub use catalog::{StoreDescriptor, VolumeHeader};
pub use error::VssError;
pub use guid::{format_guid, VSS_IDENTIFIER};
pub use store::{AttributeFlags, StoreBlockHeader, StoreInfo};

/// A read-only view over the Volume Shadow Copy metadata of an NTFS volume.
///
/// Construct with [`VssVolume::open`] over a `Read + Seek` positioned at the
/// start of the NTFS volume. The catalog of stores is read eagerly (it is
/// small); each store's [`StoreInfo`] is read lazily via
/// [`VssVolume::store_info`].
#[derive(Debug)]
pub struct VssVolume<R> {
    reader: R,
    volume_size: u64,
    has_vss_header: bool,
    catalog_offset: u64,
    stores: Vec<StoreDescriptor>,
}

impl<R: Read + Seek> VssVolume<R> {
    /// Open a VSS view over a positioned NTFS volume reader.
    ///
    /// Reads the volume header at `0x1E00`; if it carries the VSS identifier and
    /// names a catalog, walks the catalog and enumerates the stores. A volume
    /// with no VSS header (the header region is zeroed) opens successfully with
    /// [`VssVolume::has_vss_header`] `== false` and zero stores.
    ///
    /// # Errors
    /// Returns [`VssError::Io`] on an underlying read/seek failure.
    pub fn open(reader: R) -> Result<Self, VssError> {
        let _ = reader;
        unimplemented!("RED: VssVolume::open")
    }

    /// Whether the volume carries a VSS volume header at `0x1E00`.
    #[must_use]
    pub fn has_vss_header(&self) -> bool {
        unimplemented!("RED: VssVolume::has_vss_header")
    }

    /// The enumerated shadow-copy store descriptors.
    #[must_use]
    pub fn stores(&self) -> &[StoreDescriptor] {
        unimplemented!("RED: VssVolume::stores")
    }

    /// The number of enumerated shadow-copy stores.
    #[must_use]
    pub fn store_count(&self) -> usize {
        unimplemented!("RED: VssVolume::store_count")
    }

    /// The catalog offset from the volume header (0 when there is no catalog).
    #[must_use]
    pub fn catalog_offset(&self) -> u64 {
        unimplemented!("RED: VssVolume::catalog_offset")
    }

    /// The total size of the underlying volume, in bytes.
    #[must_use]
    pub fn volume_size(&self) -> u64 {
        unimplemented!("RED: VssVolume::volume_size")
    }

    /// Read and decode the store information for store `index`.
    ///
    /// # Errors
    /// - [`VssError::StoreIndexOutOfRange`] if `index` is past the last store.
    /// - [`VssError::StoreInfoUnavailable`] if the store has no type-0x03
    ///   catalog pointer.
    /// - [`VssError::StoreOffsetOutOfBounds`] if the store-header offset runs
    ///   past the end of the volume.
    /// - [`VssError::Io`] on an underlying read/seek failure.
    pub fn store_info(&mut self, index: usize) -> Result<StoreInfo, VssError> {
        let _ = index;
        unimplemented!("RED: VssVolume::store_info")
    }
}
