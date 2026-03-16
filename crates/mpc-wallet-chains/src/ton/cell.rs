//! TON Cell / BOC (Bag of Cells) encoding.
//!
//! TON stores all data in a tree of Cells. Each Cell contains up to 1023 data bits
//! and up to 4 references to other Cells. BOC is the serialization format.
//!
//! Cell hash = SHA-256(d1 || d2 || data || depth(ref0) || depth(ref1) || ... || hash(ref0) || hash(ref1) || ...)
//! where d1 = refs_count + 8*is_exotic, d2 = ceil(data_bits / 8) + floor(data_bits / 8)

use sha2::{Digest, Sha256};

/// A TON Cell with proper descriptor-based hashing.
#[derive(Debug, Clone)]
pub struct Cell {
    /// Data bytes.
    pub data: Vec<u8>,
    /// Number of data bits (may be less than data.len() * 8).
    pub data_bits: usize,
    /// References to child cells.
    pub refs: Vec<Cell>,
}

impl Cell {
    /// Create a new cell with data (all bits used).
    pub fn new(data: Vec<u8>) -> Self {
        let data_bits = data.len() * 8;
        Self {
            data,
            data_bits,
            refs: Vec::new(),
        }
    }

    /// Create a new cell with data and references.
    pub fn with_refs(data: Vec<u8>, refs: Vec<Cell>) -> Self {
        let data_bits = data.len() * 8;
        Self {
            data,
            data_bits,
            refs,
        }
    }

    /// Compute the depth of this cell tree.
    pub fn depth(&self) -> u16 {
        if self.refs.is_empty() {
            0
        } else {
            1 + self.refs.iter().map(|r| r.depth()).max().unwrap_or(0)
        }
    }

    /// Compute the SHA-256 representation hash of this cell.
    ///
    /// Cell hash = SHA-256(d1 || d2 || data || ref_depths || ref_hashes)
    /// d1 = refs_count (lower 3 bits) + level_mask (upper 5 bits, 0 for ordinary)
    /// d2 = ceil(data_bits / 8) + floor(data_bits / 8)
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();

        // d1: refs_descriptor = refs_count | (is_exotic << 3) | (level_mask << 5)
        let d1 = self.refs.len() as u8; // ordinary cell, level 0

        // d2: bits_descriptor = ceil(bits/8) + floor(bits/8)
        let d2 = (self.data_bits.div_ceil(8) + self.data_bits / 8) as u8;

        hasher.update([d1]);
        hasher.update([d2]);
        hasher.update(&self.data);

        // Append depth of each reference (2 bytes BE each)
        for r in &self.refs {
            hasher.update(r.depth().to_be_bytes());
        }
        // Append hash of each reference
        for r in &self.refs {
            hasher.update(r.hash());
        }

        hasher.finalize().to_vec()
    }

    /// Serialize this cell tree to BOC (Bag of Cells) format.
    ///
    /// Simplified BOC: [magic(4)] [flags(1)] [cell_count(1)] [root_count(1)] [cells...]
    pub fn to_boc(&self) -> Vec<u8> {
        let mut cells = Vec::new();
        self.collect_cells(&mut cells);

        let mut boc = Vec::new();
        // BOC magic bytes (reach BOC)
        boc.extend_from_slice(&[0xB5, 0xEE, 0x9C, 0x72]);
        // Flags + size
        boc.push(0x01); // has_idx = 0, has_crc32c = 0, has_cache_bits = 0, size_bytes = 1
        boc.push(cells.len() as u8); // cell count
        boc.push(1); // root count = 1
        boc.push(0); // absent count = 0
                     // Total cells data size (2 bytes)
        let total_size: usize = cells.iter().map(|c| 2 + c.data.len() + 1).sum();
        boc.extend_from_slice(&(total_size as u16).to_be_bytes());
        // Root index
        boc.push(0);
        // Serialize each cell
        for cell in &cells {
            // d1 || d2 || data
            let d1 = cell.refs.len() as u8;
            let d2 = (cell.data_bits.div_ceil(8) + cell.data_bits / 8) as u8;
            boc.push(d1);
            boc.push(d2);
            boc.extend_from_slice(&cell.data);
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

/// Build a TON internal transfer message as a Cell.
pub fn build_transfer_cell(
    dest_workchain: i8,
    dest_hash: &[u8; 32],
    amount_nanoton: u64,
    bounce: bool,
) -> Cell {
    let mut data = Vec::new();
    // Internal message header bits (simplified)
    // ihr_disabled(1)=1 | bounce(1) | bounced(1)=0 | src(00) | dest_prefix
    let flags: u8 = 0b11000000 | if bounce { 0b01000000 } else { 0 };
    data.push(flags);
    // Destination workchain
    data.push(dest_workchain as u8);
    // Destination address hash (32 bytes)
    data.extend_from_slice(dest_hash);
    // Amount in nanotons (variable length, stored as 4-bit length + value)
    data.extend_from_slice(&amount_nanoton.to_be_bytes());
    // Other TLB fields (currencies, ihr_fee, fwd_fee, created_lt, created_at) = 0
    data.extend_from_slice(&[0u8; 8]);

    Cell::new(data)
}
