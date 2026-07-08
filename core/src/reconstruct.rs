//! Phase-2 copy-on-write snapshot reconstruction.
//!
//! Given a store's block-descriptor list (the 0x0003 diff-area chain) and store
//! bitmap (the 0x0006 chain), this module materializes the snapshot's view of
//! any 16384-byte volume block by overlaying the copy-on-write data saved in the
//! store on top of the live volume.
//!
//! The algorithm is the one validated byte-for-byte against libvshadow
//! (`pyvshadow`) over 1,415 blocks of the Magnet PC-MUS-001.E01 image — see
//! `docs/RECONSTRUCTION.md`. For one block at volume offset `off` (`bn = off /
//! 16384`, `base = bn * 16384`):
//!
//! - **Descriptor set non-empty:** the base is the last *plain* descriptor's
//!   store block (a descriptor with none of forwarder/overlay/not-used set), or
//!   the live volume block when there is no plain. Then each *overlay* descriptor
//!   (overlay set, not-used clear) replaces the 512-byte sub-blocks selected by
//!   its allocation bitmap.
//! - **Descriptor set empty, bitmap bit set:** the block was unallocated in the
//!   snapshot — 16384 zero bytes.
//! - **Descriptor set empty, bitmap bit clear:** live passthrough.
//!
//! Every offset read from the image is range-checked against the volume before
//! seeking: a corrupt descriptor never panics or reads out of bounds — a
//! plain/live block that is out of range reconstructs as zeros, and an
//! out-of-range overlay contributes nothing (its sub-blocks are skipped).

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

use crate::block::BlockDescriptor;
use crate::catalog::BLOCK_SIZE;
use crate::error::VssError;
use crate::store::{StoreBlockHeader, STORE_BLOCK_HEADER_LEN};
use crate::VssVolume;

/// Record type of a block-descriptor-list (diff-area) block.
const DIFF_AREA_RECORD_TYPE: u32 = 0x0003;

/// Record type of a store-bitmap block.
const BITMAP_RECORD_TYPE: u32 = 0x0006;

/// Length of one block descriptor, in bytes.
const BLOCK_DESCRIPTOR_LEN: usize = 32;

/// Number of 512-byte sub-blocks an overlay allocation bitmap addresses.
const SUB_BLOCK_COUNT: usize = 32;

/// Size of one overlay sub-block (`16384 / 32`), in bytes.
const SUB_BLOCK_SIZE: usize = BLOCK_SIZE / SUB_BLOCK_COUNT;

/// Upper bound on store blocks walked in one chain, mirroring the catalog walk's
/// cap so a corrupt or looping diff-area/bitmap chain is bounded.
const MAX_STORE_BLOCKS: usize = 1 << 20;

/// A reconstructed, read-only view of one shadow copy — the snapshot's view of
/// the volume, materialized block by block on demand.
///
/// Built by [`VssVolume::snapshot`]; borrows the volume's reader mutably so
/// reconstruction can pull live and store blocks lazily (the volumes are far too
/// large to hold in memory).
pub struct Snapshot<'v, R> {
    reader: &'v mut R,
    volume_size: u64,
    /// Diff-area block descriptors keyed by their original (volume) offset.
    block_map: BTreeMap<u64, Vec<BlockDescriptor>>,
    /// Concatenated store bitmap; bit `n` set ⇒ volume block `n` was unallocated.
    bitmap: Vec<u8>,
}

impl<R: Read + Seek> VssVolume<R> {
    /// Build a reconstructed [`Snapshot`] of store `index`.
    ///
    /// Walks the store's block-descriptor list and bitmap eagerly (both are
    /// small relative to the volume), then borrows the reader so
    /// [`Snapshot::read_block`] / [`Snapshot::read_at`] can materialize blocks.
    ///
    /// # Errors
    /// - [`VssError::StoreIndexOutOfRange`] if `index` is past the last store.
    /// - [`VssError::StoreInfoUnavailable`] if the store has no type-0x03 catalog
    ///   pointer (so neither the store-header nor the bitmap offset is known).
    /// - [`VssError::Io`] on an underlying read/seek failure.
    pub fn snapshot(&mut self, index: usize) -> Result<Snapshot<'_, R>, VssError> {
        let (store_header_offset, store_bitmap_offset) = {
            let count = self.stores.len();
            let d = self
                .stores
                .get(index)
                .ok_or(VssError::StoreIndexOutOfRange { index, count })?;
            let header = d
                .store_header_offset
                .ok_or(VssError::StoreInfoUnavailable { index })?;
            // The bitmap offset is captured from the same type-0x03 entry as the
            // header, so it is present whenever the header is.
            let bitmap = d
                .store_bitmap_offset
                .ok_or(VssError::StoreInfoUnavailable { index })?;
            (header, bitmap)
        };

        // The block-descriptor list is the block immediately after the store
        // header, chaining via `next_offset` like every store-block chain.
        let diff_start = store_header_offset.saturating_add(BLOCK_SIZE as u64);
        let block_map = build_block_map(&mut self.reader, diff_start, self.volume_size)?;
        let bitmap = build_bitmap(&mut self.reader, store_bitmap_offset, self.volume_size)?;

        Ok(Snapshot {
            reader: &mut self.reader,
            volume_size: self.volume_size,
            block_map,
            bitmap,
        })
    }
}

impl<R: Read + Seek> Snapshot<'_, R> {
    /// Whether volume block `block_number` was unallocated in the snapshot (its
    /// store-bitmap bit is set). Out-of-range block numbers read as allocated.
    #[must_use]
    fn is_unallocated(&self, block_number: u64) -> bool {
        let byte = block_number / 8;
        let bit = (block_number % 8) as u32;
        usize::try_from(byte)
            .ok()
            .and_then(|i| self.bitmap.get(i))
            .is_some_and(|b| b & (1u8 << bit) != 0)
    }

    /// Reconstruct the single aligned 16384-byte block containing `offset`.
    ///
    /// `offset` need not be block-aligned; the block it falls in is reconstructed
    /// in full. A block at or past the end of the volume reconstructs as zeros.
    ///
    /// # Errors
    /// [`VssError::Io`] on an underlying read/seek failure.
    pub fn read_block(&mut self, offset: u64) -> Result<[u8; BLOCK_SIZE], VssError> {
        let block_number = offset / BLOCK_SIZE as u64;
        let base = block_number.saturating_mul(BLOCK_SIZE as u64);
        let mut out = [0u8; BLOCK_SIZE];

        match self.block_map.get(&base) {
            Some(descriptors) if !descriptors.is_empty() => {
                // Base data: the last plain descriptor's store block, or the live
                // volume block when the block has no plain descriptor. A plain
                // descriptor has none of forwarder/overlay/not-used set.
                let last_plain = descriptors.iter().rfind(|d| {
                    !d.flags.is_forwarder() && !d.flags.is_overlay() && !d.flags.is_not_used()
                });
                let base_source = last_plain.map_or(base, |d| d.store_offset);
                read_block_at(self.reader, base_source, self.volume_size, &mut out)?;

                // Overlay descriptors patch in their allocated 512-byte sub-blocks.
                for d in descriptors
                    .iter()
                    .filter(|d| d.flags.is_overlay() && !d.flags.is_not_used())
                {
                    let mut overlay = [0u8; BLOCK_SIZE];
                    if read_block_at(self.reader, d.store_offset, self.volume_size, &mut overlay)? {
                        apply_overlay(&mut out, &overlay, d.allocation_bitmap);
                    }
                }
                Ok(out)
            }
            _ => {
                if self.is_unallocated(block_number) {
                    Ok(out) // already zeroed
                } else {
                    read_block_at(self.reader, base, self.volume_size, &mut out)?;
                    Ok(out)
                }
            }
        }
    }

    /// Reconstruct an arbitrary-length, arbitrary-offset read, materializing each
    /// spanned block and copying the requested slice out.
    ///
    /// Bytes at or past the end of the volume read as zeros.
    ///
    /// # Errors
    /// [`VssError::Io`] on an underlying read/seek failure.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), VssError> {
        let mut written = 0usize;
        let mut cursor = offset;
        while written < buf.len() {
            let base = (cursor / BLOCK_SIZE as u64).saturating_mul(BLOCK_SIZE as u64);
            let within = (cursor - base) as usize;
            let block = self.read_block(base)?;
            let n = (BLOCK_SIZE - within).min(buf.len() - written);
            buf[written..written + n].copy_from_slice(&block[within..within + n]);
            written += n;
            cursor = cursor.saturating_add(n as u64);
        }
        Ok(())
    }
}

/// Overwrite the sub-blocks of `out` selected by `allocation_bitmap` (bit `i`,
/// LSB-first) with `overlay`'s corresponding 512-byte sub-block.
fn apply_overlay(out: &mut [u8; BLOCK_SIZE], overlay: &[u8; BLOCK_SIZE], allocation_bitmap: u32) {
    for i in 0..SUB_BLOCK_COUNT {
        if allocation_bitmap & (1u32 << i) != 0 {
            let start = i * SUB_BLOCK_SIZE;
            let end = start + SUB_BLOCK_SIZE;
            out[start..end].copy_from_slice(&overlay[start..end]);
        }
    }
}

/// Read the 16384-byte block at volume `offset` into `out`.
///
/// Returns `Ok(true)` when the block was fully in range and read, `Ok(false)`
/// when `offset` runs past the end of the volume (in which case `out` is left
/// zeroed and the caller treats the source as contributing nothing).
fn read_block_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    volume_size: u64,
    out: &mut [u8; BLOCK_SIZE],
) -> Result<bool, VssError> {
    match offset.checked_add(BLOCK_SIZE as u64) {
        Some(end) if end <= volume_size => {
            reader.seek(SeekFrom::Start(offset))?;
            reader.read_exact(out)?;
            Ok(true)
        }
        _ => {
            *out = [0u8; BLOCK_SIZE];
            Ok(false)
        }
    }
}

/// Walk the 0x0003 block-descriptor (diff-area) chain from `first`, collecting
/// every descriptor keyed by its original (volume) offset.
///
/// Bounded exactly like the catalog walk: a visited-set breaks cycles,
/// [`MAX_STORE_BLOCKS`] caps the chain length, and every block offset is
/// range-checked against the volume before it is read. A block whose record type
/// is not 0x0003 stops the walk. Within a block, a fully-zero 32-byte record
/// terminates that block's descriptor list.
fn build_block_map<R: Read + Seek>(
    reader: &mut R,
    first: u64,
    volume_size: u64,
) -> Result<BTreeMap<u64, Vec<BlockDescriptor>>, VssError> {
    let mut map: BTreeMap<u64, Vec<BlockDescriptor>> = BTreeMap::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut next = first;
    let mut blocks = 0usize;

    while next != 0 && blocks < MAX_STORE_BLOCKS {
        if !visited.insert(next) {
            break; // cycle
        }
        match next.checked_add(BLOCK_SIZE as u64) {
            Some(end) if end <= volume_size => {}
            _ => break, // out of range / overflow
        }

        reader.seek(SeekFrom::Start(next))?;
        let mut block = vec![0u8; BLOCK_SIZE];
        reader.read_exact(&mut block)?;
        let header = StoreBlockHeader::parse(&block);
        if header.record_type != DIFF_AREA_RECORD_TYPE {
            break;
        }

        let mut off = STORE_BLOCK_HEADER_LEN;
        while off + BLOCK_DESCRIPTOR_LEN <= BLOCK_SIZE {
            let record = &block[off..off + BLOCK_DESCRIPTOR_LEN];
            if record.iter().all(|&x| x == 0) {
                break; // zero record terminates this block's descriptors
            }
            let descriptor = BlockDescriptor::parse(record);
            map.entry(descriptor.original_offset)
                .or_default()
                .push(descriptor);
            off += BLOCK_DESCRIPTOR_LEN;
        }

        blocks += 1;
        next = header.next_offset;
    }

    Ok(map)
}

/// Walk the 0x0006 store-bitmap chain from `first`, concatenating each block's
/// payload (the bytes after its 128-byte header) in `relative_offset` order into
/// one contiguous bitmap.
///
/// Bounded the same three ways as [`build_block_map`]; a block whose record type
/// is not 0x0006 stops the walk.
fn build_bitmap<R: Read + Seek>(
    reader: &mut R,
    first: u64,
    volume_size: u64,
) -> Result<Vec<u8>, VssError> {
    let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut next = first;
    let mut blocks = 0usize;

    while next != 0 && blocks < MAX_STORE_BLOCKS {
        if !visited.insert(next) {
            break; // cycle
        }
        match next.checked_add(BLOCK_SIZE as u64) {
            Some(end) if end <= volume_size => {}
            _ => break, // out of range / overflow
        }

        reader.seek(SeekFrom::Start(next))?;
        let mut block = vec![0u8; BLOCK_SIZE];
        reader.read_exact(&mut block)?;
        let header = StoreBlockHeader::parse(&block);
        if header.record_type != BITMAP_RECORD_TYPE {
            break;
        }

        pieces.push((
            header.relative_offset,
            block[STORE_BLOCK_HEADER_LEN..BLOCK_SIZE].to_vec(),
        ));

        blocks += 1;
        next = header.next_offset;
    }

    pieces.sort_by_key(|(rel, _)| *rel);
    let mut bitmap = Vec::with_capacity(
        pieces
            .len()
            .saturating_mul(BLOCK_SIZE - STORE_BLOCK_HEADER_LEN),
    );
    for (_, payload) in pieces {
        bitmap.extend_from_slice(&payload);
    }
    Ok(bitmap)
}
