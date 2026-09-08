//! Piece picker, bitfield, and choking algorithm for the synapse rewrite. Pure logic,
//! no I/O and no async - the `Engine` (Stage 3, not yet built) drives these from
//! whatever async event loop actually talks to peers. See `doc/REWRITE_ROADMAP.md`.

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
