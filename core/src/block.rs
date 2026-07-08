//! Typed diff-area records: the block descriptor and store block range.
//!
//! Phase 1 parses these two records so a consumer sees the copy-on-write mapping
//! structurally. The full snapshot-reconstruction engine (overlaying diff-area
//! blocks to materialize a snapshot's view of the volume) is Phase 2 and is
//! deliberately **not** implemented here.

/// Length of a block descriptor record, in bytes.
pub const BLOCK_DESCRIPTOR_LEN: usize = 32;

/// Length of a store block range record, in bytes.
pub const STORE_BLOCK_RANGE_LEN: usize = 24;

/// Flags on a block descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDescriptorFlags(pub u32);

impl BlockDescriptorFlags {
    /// Forwarder — maps to the next block's original offset.
    pub const FORWARDER: u32 = 0x01;
    /// Overlay — the allocation bitmap defines how the block is filled.
    pub const OVERLAY: u32 = 0x02;
    /// Not used — the block is ignored.
    pub const NOT_USED: u32 = 0x04;

    /// The raw flag bits.
    #[must_use]
    pub fn bits(self) -> u32 {
        unimplemented!("RED: BlockDescriptorFlags::bits")
    }

    /// Whether any of the given flag bits are set.
    #[must_use]
    pub fn contains(self, flag: u32) -> bool {
        let _ = flag;
        unimplemented!("RED: BlockDescriptorFlags::contains")
    }

    /// Whether the forwarder flag is set.
    #[must_use]
    pub fn is_forwarder(self) -> bool {
        unimplemented!("RED: BlockDescriptorFlags::is_forwarder")
    }

    /// Whether the overlay flag is set.
    #[must_use]
    pub fn is_overlay(self) -> bool {
        unimplemented!("RED: BlockDescriptorFlags::is_overlay")
    }

    /// Whether the not-used flag is set.
    #[must_use]
    pub fn is_not_used(self) -> bool {
        unimplemented!("RED: BlockDescriptorFlags::is_not_used")
    }
}

/// A 32-byte diff-area block descriptor: it maps an original volume block to the
/// copy-on-write block saved in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDescriptor {
    /// Original data block offset (volume-relative).
    pub original_offset: u64,
    /// Relative store data block offset (store-relative).
    pub relative_store_offset: u64,
    /// Store data block offset (volume-relative).
    pub store_offset: u64,
    /// Flags.
    pub flags: BlockDescriptorFlags,
    /// Allocation bitmap (used when the overlay flag is set).
    pub allocation_bitmap: u32,
}

impl BlockDescriptor {
    /// Parse a 32-byte block descriptor.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Self {
        let _ = buf;
        unimplemented!("RED: BlockDescriptor::parse")
    }
}

/// A 24-byte store block range record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreBlockRange {
    /// Store block range start offset (volume-relative).
    pub store_offset: u64,
    /// Relative block range start offset (store-relative).
    pub relative_offset: u64,
    /// Block range size, in bytes.
    pub range_size: u64,
}

impl StoreBlockRange {
    /// Parse a 24-byte store block range record.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Self {
        let _ = buf;
        unimplemented!("RED: StoreBlockRange::parse")
    }
}
