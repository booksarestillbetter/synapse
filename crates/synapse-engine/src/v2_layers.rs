//! Fetching a BitTorrent v2 file's piece layer from peers (BEP 52 `hash request`).
//!
//! A v2 `.torrent` normally carries each file's piece layer, but a v2 *magnet* delivers only
//! the info dictionary, so the hashes pieces are verified against have to come from peers.
//! Every chunk a peer sends is checked against the file's `pieces root` with the uncle-hash
//! proof it must include, so nothing a peer sends is trusted until it proves it belongs to
//! the root, and the assembled layer is checked against the root once more before use.

use std::time::{Duration, Instant};

use synapse_meta::merkle::{
    root_from_piece_layer, verify_piece_layer_chunk, BLOCK_SIZE, MAX_HASHES_PER_CHUNK,
};

use crate::peer::PeerId;

/// How long a chunk request may go unanswered before it is asked of another peer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// After a `hash reject` a chunk is not re-requested for this long.
const REJECT_BACKOFF: Duration = Duration::from_secs(30);
/// Chunk requests in flight at once.
const MAX_OUTSTANDING: usize = 4;

/// The shape of one file's piece layer within its padded Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerGeometry {
    /// Tree layer of the piece hashes (0 = 16 KiB blocks): `log2(piece_len / 16 KiB)`.
    pub base: u32,
    /// Nodes on the (padded) piece layer.
    pub level_size: usize,
    /// Real pieces in the file (the rest of the layer is padding).
    pub pieces: usize,
    /// Hashes per request: a power of two, at most `MAX_HASHES_PER_CHUNK`.
    pub chunk: usize,
    /// Uncle hashes needed to prove a chunk up to the root.
    pub proof_layers: u32,
}

impl LayerGeometry {
    /// `None` when the file needs no piece layer (it fits in one piece) or `piece_len` is not
    /// a power of two of at least 16 KiB (BEP 52 requires it).
    pub fn for_file(file_len: u64, piece_len: u32) -> Option<Self> {
        let block = BLOCK_SIZE as u64;
        let piece_len = u64::from(piece_len);
        if file_len <= piece_len || !piece_len.is_power_of_two() || piece_len < block {
            return None;
        }
        let blocks = file_len.div_ceil(block);
        let leaves = blocks.next_power_of_two();
        let height = leaves.trailing_zeros();
        let base = (piece_len / block).trailing_zeros();
        let level_size = (leaves >> base) as usize;
        let pieces = file_len.div_ceil(piece_len) as usize;
        let chunk = level_size.min(MAX_HASHES_PER_CHUNK);
        let proof_layers = height - base - chunk.trailing_zeros();
        Some(LayerGeometry {
            base,
            level_size,
            pieces,
            chunk,
            proof_layers,
        })
    }

    fn chunks(&self) -> usize {
        self.pieces.div_ceil(self.chunk)
    }
}

enum Chunk {
    Missing { retry_at: Instant },
    Requested { peer: PeerId, at: Instant },
    Done,
}

/// A request to send: ask `peer` for `count` hashes at `index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerRequest {
    pub peer: PeerId,
    pub index: u32,
    pub count: u32,
}

pub struct LayerFetch {
    root: [u8; 32],
    geo: LayerGeometry,
    hashes: Vec<Option<[u8; 32]>>,
    chunks: Vec<Chunk>,
}

impl LayerFetch {
    pub fn new(root: [u8; 32], file_len: u64, piece_len: u32) -> Option<Self> {
        let geo = LayerGeometry::for_file(file_len, piece_len)?;
        let now = Instant::now();
        Some(LayerFetch {
            root,
            hashes: vec![None; geo.pieces],
            chunks: (0..geo.chunks())
                .map(|_| Chunk::Missing { retry_at: now })
                .collect(),
            geo,
        })
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn geometry(&self) -> LayerGeometry {
        self.geo
    }

    /// Assigns chunks that are missing (or whose request timed out) to `peers`, round-robin,
    /// keeping at most `MAX_OUTSTANDING` requests in flight.
    pub fn due_requests(&mut self, now: Instant, peers: &[PeerId]) -> Vec<LayerRequest> {
        if peers.is_empty() {
            return Vec::new();
        }
        let mut outstanding = self.chunks.iter().filter(|c| matches!(c, Chunk::Requested { at, .. } if now.duration_since(*at) < REQUEST_TIMEOUT)).count();
        let mut out = Vec::new();
        let mut next_peer = 0usize;
        for (i, chunk) in self.chunks.iter_mut().enumerate() {
            if outstanding >= MAX_OUTSTANDING {
                break;
            }
            let due = match chunk {
                Chunk::Missing { retry_at } => now >= *retry_at,
                Chunk::Requested { at, .. } => now.duration_since(*at) >= REQUEST_TIMEOUT,
                Chunk::Done => false,
            };
            if !due {
                continue;
            }
            let peer = peers[next_peer % peers.len()];
            next_peer += 1;
            *chunk = Chunk::Requested { peer, at: now };
            outstanding += 1;
            out.push(LayerRequest {
                peer,
                index: (i * self.geo.chunk) as u32,
                count: self.geo.chunk as u32,
            });
        }
        out
    }

    /// A peer went away: chunks it had been asked for are due again immediately.
    pub fn peer_disconnected(&mut self, gone: PeerId) {
        let now = Instant::now();
        for c in &mut self.chunks {
            if matches!(c, Chunk::Requested { peer, .. } if *peer == gone) {
                *c = Chunk::Missing { retry_at: now };
            }
        }
    }

    /// A `hash reject` for the chunk at `index`: try again later, from anyone.
    pub fn on_reject(&mut self, index: u32, now: Instant) {
        let i = index as usize / self.geo.chunk;
        if let Some(c) = self.chunks.get_mut(i) {
            if matches!(c, Chunk::Requested { .. }) {
                *c = Chunk::Missing {
                    retry_at: now + REJECT_BACKOFF,
                };
            }
        }
    }

    /// Handles a `hashes` message for this file. `payload` is `count` hashes followed by
    /// `proof_layers` uncle hashes. Returns `Ok(Some(layer))` when this chunk completed the
    /// layer (the concatenated, verified piece hashes), `Ok(None)` when it was accepted (or
    /// was a harmless repeat), and `Err(())` when it does not verify: wrong geometry, or hashes
    /// that do not prove out against the root.
    #[allow(clippy::result_unit_err)]
    pub fn on_hashes(
        &mut self,
        base: u32,
        index: u32,
        count: u32,
        proof_layers: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, ()> {
        let g = self.geo;
        let (count, index) = (count as usize, index as usize);
        if base != g.base
            || count == 0
            || count > g.chunk
            || index >= g.level_size
            || proof_layers as usize > 64
            || payload.len() != (count + proof_layers as usize) * 32
        {
            return Err(());
        }
        let cells = payload.as_chunks::<32>().0;
        let (hashes, proof) = cells.split_at(count);
        if !verify_piece_layer_chunk(&self.root, g.level_size, index, hashes, proof) {
            return Err(());
        }
        // The chunk is proven part of the tree; keep the real (non-padding) hashes.
        for (offset, h) in hashes.iter().enumerate() {
            if let Some(slot) = self.hashes.get_mut(index + offset) {
                *slot = Some(*h);
            }
        }
        // A verified chunk may be larger than our own chunk size (a peer answering a request
        // of its choosing) or smaller; mark every request-chunk it fully covers as done.
        for (i, chunk) in self.chunks.iter_mut().enumerate() {
            let lo = i * g.chunk;
            let hi = ((i + 1) * g.chunk).min(g.pieces);
            if (lo..hi).all(|p| self.hashes[p].is_some()) {
                *chunk = Chunk::Done;
            }
        }
        if self.hashes.iter().all(Option::is_some) {
            let layer: Vec<u8> = self
                .hashes
                .iter()
                .flat_map(|h| h.expect("checked"))
                .collect();
            // Belt and braces: the assembled layer must reproduce the root by itself.
            let piece_len = BLOCK_SIZE << g.base;
            if root_from_piece_layer(&layer, piece_len) == Some(self.root) {
                return Ok(Some(layer));
            }
            return Err(());
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synapse_meta::merkle::{
        compute_file_merkle_root, compute_file_piece_layer, PieceLayerTree,
    };

    const PIECE_LEN: usize = BLOCK_SIZE * 2;

    fn file(len: usize) -> (Vec<u8>, [u8; 32], PieceLayerTree) {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let layer = compute_file_piece_layer(&data, PIECE_LEN).concat();
        let tree = PieceLayerTree::new(&layer, PIECE_LEN).unwrap();
        (data.clone(), compute_file_merkle_root(&data), tree)
    }

    /// Payload a well-behaved peer would send for a request.
    fn answer(tree: &PieceLayerTree, geo: LayerGeometry, req: LayerRequest) -> Vec<u8> {
        let (hashes, proof) = tree
            .respond(
                req.index as usize,
                req.count as usize,
                geo.proof_layers as usize,
            )
            .unwrap();
        hashes.into_iter().chain(proof).flatten().collect()
    }

    #[test]
    fn geometry_matches_the_tree_for_various_file_sizes() {
        // 40 blocks -> 64 leaves? no: 40 blocks pads to 64 leaves, piece = 2 blocks -> 32 level, 20 real pieces.
        let g = LayerGeometry::for_file((BLOCK_SIZE * 40) as u64, PIECE_LEN as u32).unwrap();
        assert_eq!(
            (g.base, g.level_size, g.pieces, g.chunk, g.proof_layers),
            (1, 32, 20, 32, 0)
        );
        // A layer bigger than one chunk needs proofs: 4096 blocks / 2 = 2048 pieces, chunks of 512.
        let g = LayerGeometry::for_file((BLOCK_SIZE * 4096) as u64, PIECE_LEN as u32).unwrap();
        assert_eq!(
            (g.level_size, g.pieces, g.chunk, g.proof_layers),
            (2048, 2048, 512, 2)
        );
        assert!(
            LayerGeometry::for_file(1000, PIECE_LEN as u32).is_none(),
            "one piece: no layer"
        );
        assert!(
            LayerGeometry::for_file(1 << 30, 100_000).is_none(),
            "piece length not a power of two"
        );
    }

    #[test]
    fn a_layer_larger_than_one_chunk_is_fetched_verified_and_assembled() {
        let (_, root, tree) = file(BLOCK_SIZE * 4100 + 17); // 2051 pieces, level of 4096? -> 2051 real
        let mut fetch =
            LayerFetch::new(root, (BLOCK_SIZE * 4100 + 17) as u64, PIECE_LEN as u32).unwrap();
        let geo = fetch.geometry();
        assert!(geo.proof_layers > 0 && geo.chunk == 512);
        let peers = [1u64, 2];
        let mut done = None;
        let mut rounds = 0;
        while done.is_none() && rounds < 20 {
            rounds += 1;
            let reqs = fetch.due_requests(Instant::now(), &peers);
            assert!(reqs.len() <= MAX_OUTSTANDING);
            for req in reqs {
                let payload = answer(&tree, geo, req);
                match fetch.on_hashes(geo.base, req.index, req.count, geo.proof_layers, &payload) {
                    Ok(Some(layer)) => done = Some(layer),
                    Ok(None) => {}
                    Err(()) => panic!("a genuine chunk must verify"),
                }
            }
        }
        let layer = done.expect("layer assembled");
        assert_eq!(layer.len(), geo.pieces * 32);
        assert_eq!(root_from_piece_layer(&layer, PIECE_LEN), Some(root));
    }

    #[test]
    fn forged_chunks_are_rejected_and_do_not_pollute_the_layer() {
        let (_, root, tree) = file(BLOCK_SIZE * 4100);
        let mut fetch =
            LayerFetch::new(root, (BLOCK_SIZE * 4100) as u64, PIECE_LEN as u32).unwrap();
        let geo = fetch.geometry();
        let req = fetch.due_requests(Instant::now(), &[7]).remove(0);
        let good = answer(&tree, geo, req);

        let mut bad = good.clone();
        bad[3] ^= 0xFF; // corrupt a hash
        assert!(fetch
            .on_hashes(geo.base, req.index, req.count, geo.proof_layers, &bad)
            .is_err());
        let mut bad_proof = good.clone();
        let n = bad_proof.len();
        bad_proof[n - 1] ^= 1; // corrupt the last uncle
        assert!(fetch
            .on_hashes(geo.base, req.index, req.count, geo.proof_layers, &bad_proof)
            .is_err());
        // Wrong geometry: base layer, oversized count, absurd index, wrong payload length.
        assert!(fetch
            .on_hashes(geo.base + 1, req.index, req.count, geo.proof_layers, &good)
            .is_err());
        assert!(fetch
            .on_hashes(
                geo.base,
                req.index,
                geo.chunk as u32 + 1,
                geo.proof_layers,
                &good
            )
            .is_err());
        assert!(fetch
            .on_hashes(geo.base, u32::MAX, req.count, geo.proof_layers, &good)
            .is_err());
        assert!(fetch
            .on_hashes(
                geo.base,
                req.index,
                req.count,
                geo.proof_layers,
                &good[..good.len() - 32]
            )
            .is_err());
        // Nothing was accepted, so the genuine chunk is still needed and still verifies.
        assert!(fetch
            .on_hashes(geo.base, req.index, req.count, geo.proof_layers, &good)
            .unwrap()
            .is_none());
    }

    #[test]
    fn unanswered_and_rejected_requests_are_retried_later() {
        let (_, root, _) = file(BLOCK_SIZE * 4100);
        let mut fetch =
            LayerFetch::new(root, (BLOCK_SIZE * 4100) as u64, PIECE_LEN as u32).unwrap();
        let t0 = Instant::now();
        let first = fetch.due_requests(t0, &[1]);
        assert_eq!(
            first.len(),
            MAX_OUTSTANDING.min(fetch.geometry().pieces.div_ceil(fetch.geometry().chunk))
        );
        // Nothing new is due while those are in flight and fresh.
        assert!(fetch
            .due_requests(t0 + Duration::from_secs(1), &[1])
            .is_empty());
        // After the timeout they are handed out again, to whoever is connected.
        let again = fetch.due_requests(t0 + REQUEST_TIMEOUT + Duration::from_secs(1), &[2]);
        assert!(!again.is_empty() && again.iter().all(|r| r.peer == 2));
        // A reject backs the chunk off.
        let idx = again[0].index;
        fetch.on_reject(idx, t0 + REQUEST_TIMEOUT);
        let soon = fetch.due_requests(t0 + REQUEST_TIMEOUT + Duration::from_secs(2), &[3]);
        assert!(soon.iter().all(|r| r.index != idx));
    }
}
