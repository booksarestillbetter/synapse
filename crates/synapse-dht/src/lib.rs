//! BEP5 Kademlia DHT for the synapse rewrite. See `doc/REWRITE_ROADMAP.md` Part 2.

pub mod bep42;
pub mod node;
pub mod proto;
pub mod routing;
pub mod sample;
pub mod storage;
pub mod updater;

pub use bep42::{generate_secure_node_id, verify_secure_node_id};
pub use node::{spawn, DhtError, DhtHandle, IterativePeersResult};
pub use sample::{
    decode_dht_scrape_response, decode_sample_infohashes_response, encode_dht_scrape_response,
    encode_sample_infohashes_response, DhtScrapeQuery, DhtScrapeResponse, SampleInfohashesQuery,
    SampleInfohashesResponse,
};
pub use storage::{DhtItem, DhtStorage, StorageError};
pub use updater::TorrentUpdatePointer;
