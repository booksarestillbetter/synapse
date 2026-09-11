//! Piece picker, bitfield, priority mapping, and choking algorithms for Synapse 2.0.
//! Pure logic, zero I/O — driven asynchronously by `synapse-engine` swarm actors.

mod bitfield;
mod choker;
mod picker;
pub mod priority;
pub mod superseed;

pub use bitfield::{Bitfield, RoaringBitfield};
pub use choker::{ChokeDecisions, Choker, PeerStats};
pub use picker::{Mode, Picker};
pub use priority::{FilePriority, PriorityMap};
pub use superseed::SuperSeeder;
