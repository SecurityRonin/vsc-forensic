//! VSS volume header (offset 0x1E00) and catalog block / entry decoding.
//!
//! The volume header names the catalog; the catalog is one or more 16 KiB
//! blocks, each a 128-byte header followed by 128-byte entries. A type-0x02
//! entry is a snapshot descriptor; the paired type-0x03 entry points at the
//! store's block header so its store-information can be read.

/// Byte offset of the VSS volume header within the NTFS volume.
pub const VSS_VOLUME_HEADER_OFFSET: u64 = 0x1E00;

/// VSS block size (catalog block and store block), in bytes.
pub const BLOCK_SIZE: usize = 16_384;

/// Length of a catalog block header, in bytes.
pub const CATALOG_BLOCK_HEADER_LEN: usize = 128;

/// Length of a single catalog entry, in bytes.
pub const CATALOG_ENTRY_LEN: usize = 128;

/// Record type of the VSS volume header (offset 20).
pub const VOLUME_HEADER_RECORD_TYPE: u32 = 0x01;

/// Record type of a catalog block header (offset 20).
pub const CATALOG_BLOCK_RECORD_TYPE: u32 = 0x02;

/// Upper bound on catalog blocks walked, to bound a corrupt/looping chain.
pub const MAX_CATALOG_BLOCKS: usize = 4096;

/// The decoded VSS volume header at [`VSS_VOLUME_HEADER_OFFSET`].
#[derive(Debug, Clone)]
pub struct VolumeHeader {
    /// Whether the 16 bytes at offset 0 are the VSS identifier GUID — i.e. this
    /// volume carries VSS metadata at all.
    pub has_vss_identifier: bool,
    /// Format version.
    pub version: u32,
    /// Record type (expected [`VOLUME_HEADER_RECORD_TYPE`]).
    pub record_type: u32,
    /// Current offset field (expected [`VSS_VOLUME_HEADER_OFFSET`]).
    pub current_offset: u64,
    /// Catalog offset (volume-relative); 0 when there is no catalog.
    pub catalog_offset: u64,
    /// Maximum store size, or 0 when unbounded.
    pub maximum_size: u64,
    /// Volume identifier GUID.
    pub volume_identifier: [u8; 16],
    /// Shadow-copy storage volume identifier GUID.
    pub storage_volume_identifier: [u8; 16],
}

impl VolumeHeader {
    /// Parse a volume header from a byte slice positioned at offset 0x1E00.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Self {
        let _ = buf;
        unimplemented!("RED: VolumeHeader::parse")
    }
}

/// A shadow-copy store as described by a catalog type-0x02 entry, augmented with
/// the store-header offset from its paired type-0x03 entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreDescriptor {
    /// Store identifier GUID (also the store's on-disk filename).
    pub store_id: [u8; 16],
    /// Shadow-copy volume size at snapshot time.
    pub volume_size: u64,
    /// Catalog sequence number.
    pub sequence: u64,
    /// Snapshot flags (0x40 = Vista/7, 0x440 = Win8 file backup).
    pub flags: u64,
    /// Shadow-copy creation time, a raw Windows FILETIME (100 ns since 1601, UTC).
    pub creation_time: u64,
    /// Volume-relative offset of the store block header (from the type-0x03
    /// entry), or `None` when the catalog has no type-0x03 entry (Win 2003 R2).
    pub store_header_offset: Option<u64>,
}

impl StoreDescriptor {
    /// The store identifier rendered as a canonical GUID string.
    #[must_use]
    pub fn store_id_string(&self) -> String {
        unimplemented!("RED: StoreDescriptor::store_id_string")
    }
}

/// One decoded catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CatalogEntry {
    /// Type 0x00 — empty padding slot.
    Empty,
    /// Type 0x02 — a snapshot descriptor.
    Snapshot(StoreDescriptor),
    /// Type 0x03 — a pointer to a store's block header.
    StorePointer {
        store_id: [u8; 16],
        store_header_offset: u64,
    },
    /// Any other entry type (0x01, unknown).
    Other,
}

/// Parse a single 128-byte catalog entry.
pub(crate) fn parse_catalog_entry(buf: &[u8]) -> CatalogEntry {
    let _ = buf;
    unimplemented!("RED: parse_catalog_entry")
}

/// Read the next-block offset (volume-relative) from a catalog block header.
pub(crate) fn catalog_next_block_offset(block: &[u8]) -> u64 {
    let _ = block;
    unimplemented!("RED: catalog_next_block_offset")
}

/// Whether a catalog block header carries the VSS identifier and catalog record
/// type — used to stop walking on a corrupt/foreign block.
pub(crate) fn is_catalog_block(block: &[u8]) -> bool {
    let _ = block;
    unimplemented!("RED: is_catalog_block")
}
