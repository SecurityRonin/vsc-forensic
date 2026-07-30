//! `vfs` feature — a reconstructed shadow copy as a `forensic_vfs::ImageSource`.
//!
//! This is the `[H]` state-history seam: forensic-vfs already speaks VSS in its
//! locator vocabulary (`Layer::Snapshot { store: SnapshotRef::VssStore(i) }`,
//! rendered `snapshot:vss,{i}`), and [`VssSnapshotSource`] is the byte source
//! that vocabulary points at — the volume as it stood when shadow copy `i` was
//! taken, addressable by offset like any other image.
//!
//! # Bridging the ownership gap
//!
//! [`crate::Snapshot`] borrows its volume and reads through `&mut self`, because
//! a `Read + Seek` cursor cannot be shared. [`ImageSource`] is the opposite: a
//! cursor-free `read_at(&self, ..)` on a `Send + Sync` handle that lives in an
//! `Arc` at every composition seam. The bridge has two halves:
//!
//! - The expensive, reader-independent half of a snapshot — the diff-area block
//!   map and the store bitmap — is built once at [`VssSnapshotSource::open`] and
//!   thereafter read-only, so it is shared by `&self` with no lock at all.
//! - Only the cursor needs exclusive access, so **one reader lives behind one
//!   `Mutex` inside one source**. Seek-then-read is not atomic, so reads of a
//!   single snapshot serialize — that is inherent to a `Read + Seek` cursor, not
//!   a choice.
//!
//! **The choice that matters is the lock's granularity, and it is per-snapshot,
//! not per-volume.** [`VssSnapshotSource::open`] takes ownership of a reader
//! rather than borrowing a shared [`crate::VssVolume`], so N shadow copies of one
//! image become N sources with N independent readers and N independent locks, and
//! they are read fully in parallel. A single `Mutex<VssVolume<R>>` shared by every
//! snapshot would have been less code and would have serialized every VSS read in
//! the process behind one lock — including reads of *different* snapshots, which
//! have nothing to contend over. The cost of the choice is one reader per
//! snapshot: over a `forensic_vfs::adapters::SourceCursor` that is a cheap
//! `Arc` clone of the underlying source, and over a file it is one file
//! descriptor.

use std::io::{Read, Seek};
use std::sync::{Mutex, PoisonError};

use forensic_vfs::{ImageSource, VfsError, VfsResult};

use crate::error::VssError;
use crate::reconstruct::SnapshotState;
use crate::VssVolume;

/// An owned, reconstructed shadow copy published as a `forensic_vfs`
/// [`ImageSource`]: positioned reads of the volume as it stood at the moment
/// store `index` was taken.
///
/// Reads are copy-on-write reconstructions, not raw passthrough — a block the
/// snapshot superseded reads from the store's diff area, and a block that was
/// unallocated in the snapshot reads as zeros even where the live volume still
/// holds data.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use forensic_vfs::{DynSource, ImageSource};
/// use vsc::vfs::VssSnapshotSource;
///
/// let source: DynSource = Arc::new(VssSnapshotSource::open(
///     std::fs::File::open("volume.raw")?,
///     0,
/// )?);
/// let mut buf = [0u8; 512];
/// let read = source.read_at(0, &mut buf)?;
/// # let _ = read;
/// # Ok(())
/// # }
/// ```
pub struct VssSnapshotSource<R> {
    /// The cursor — the only part needing exclusive access, so the only part
    /// behind the lock (see the module docs on granularity).
    reader: Mutex<R>,
    /// The reconstruction inputs: immutable after `open`, shared by `&self`.
    state: SnapshotState,
    /// The addressable size of the reconstructed volume, in bytes.
    volume_size: u64,
}

impl<R: Read + Seek> VssSnapshotSource<R> {
    /// Open shadow copy `index` of the VSS volume behind `reader`, taking
    /// ownership of the reader.
    ///
    /// Walks the catalog and the store's diff-area and bitmap chains up front,
    /// so every later read is a bounded overlay over already-decoded metadata.
    ///
    /// # Errors
    /// - [`VssError::StoreIndexOutOfRange`] if `index` is past the last store.
    /// - [`VssError::StoreInfoUnavailable`] if the store has no type-0x03 catalog
    ///   pointer, so its diff area cannot be located.
    /// - [`VssError::Io`] on an underlying read/seek failure.
    pub fn open(reader: R, index: usize) -> Result<Self, VssError> {
        let mut volume = VssVolume::open(reader)?;
        let state = volume.snapshot_state(index)?;
        let volume_size = volume.volume_size();
        Ok(Self {
            reader: Mutex::new(volume.reader),
            state,
            volume_size,
        })
    }
}

impl<R: Read + Seek + Send> ImageSource for VssSnapshotSource<R> {
    fn len(&self) -> u64 {
        self.volume_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // ImageSource contract: at/after EOF read 0 bytes; a read straddling the
        // end returns the available prefix rather than erroring.
        let Some(remaining) = self.volume_size.checked_sub(offset) else {
            return Ok(0);
        };
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if want == 0 {
            return Ok(0);
        }

        // A panic while holding this lock would need a panic inside a
        // `forbid(unsafe)`, panic-free-by-lint reader, so poisoning is not
        // reachable; recovering the guard keeps that unreachable case from
        // turning a read into an error (and keeps the reader out of `unwrap`).
        let mut reader = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        self.state
            .read_at(&mut *reader, offset, &mut buf[..want])
            .map_err(|source| VfsError::Io {
                op: "vss snapshot read",
                source,
            })?;
        Ok(want)
    }
}
