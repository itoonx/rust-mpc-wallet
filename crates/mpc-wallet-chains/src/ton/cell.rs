//! TON Cell / BOC (Bag of Cells) encoding.
//!
//! TON stores all data in a tree of Cells. Each Cell contains up to 1023 data bits
//! and up to 4 references to other Cells. BOC is the serialization format.
//!
//! This is a simplified implementation for transfer messages.

use sha2::{Digest, Sha256};

/// A simplified TON Cell.
#[derive(Debug, Clone)]
pub struct Cell {
    /// Data bytes (simplified — real TON uses bit-level addressing).
    pub data: Vec<u8>,
    /// References to child cells.
    pub refs: Vec<Cell>,
}

impl Cell {
    /// Create a new cell with data and no references.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            refs: Vec::new(),
        }
    }

    /// Create a new cell with data and references.
    pub fn with_refs(data: Vec<u8>, refs: Vec<Cell>) -> Self {
        Self { data, refs }
    }

    /// Compute the SHA-256 hash of this cell (simplified representation hash).
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        // Hash data length + data
        hasher.update((self.data.len() as u32).to_be_bytes());
        hasher.update(&self.data);
        // Hash number of refs
        hasher.update([self.refs.len() as u8]);
        // Hash each ref's hash
        for r in &self.refs {
            hasher.update(r.hash());
        }
        hasher.finalize().to_vec()
    }

    /// Serialize this cell tree to a simplified BOC (Bag of Cells) format.
    ///
    /// Simplified BOC: [magic(4)] [cell_count(1)] [cell_data...]
    pub fn to_boc(&self) -> Vec<u8> {
        let mut cells = Vec::new();
        self.collect_cells(&mut cells);

        let mut boc = Vec::new();
        // BOC magic bytes
        boc.extend_from_slice(&[0xB5, 0xEE, 0x9C, 0x72]);
        // Cell count
        boc.push(cells.len() as u8);
        // Serialize each cell: [data_len(2)] [data] [ref_count(1)]
        for cell in &cells {
            let len = cell.data.len() as u16;
            boc.extend_from_slice(&len.to_be_bytes());
            boc.extend_from_slice(&cell.data);
            boc.push(cell.refs.len() as u8);
        }
        boc
    }

    fn collect_cells<'a>(&'a self, out: &mut Vec<&'a Cell>) {
        out.push(self);
        for r in &self.refs {
            r.collect_cells(out);
        }
    }
}

/// Build a simplified TON internal transfer message as a Cell.
pub fn build_transfer_cell(
    dest_workchain: i8,
    dest_hash: &[u8; 32],
    amount_nanoton: u64,
    bounce: bool,
) -> Cell {
    let mut data = Vec::new();
    // Message flags
    data.push(if bounce { 0x01 } else { 0x00 });
    // Destination workchain
    data.push(dest_workchain as u8);
    // Destination address hash
    data.extend_from_slice(dest_hash);
    // Amount in nanotons
    data.extend_from_slice(&amount_nanoton.to_be_bytes());

    Cell::new(data)
}
