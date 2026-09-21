//! BEP5 Kademlia DHT for the synapse rewrite. See `doc/REWRITE_ROADMAP.md` Part 2.

pub mod bep42;
pub mod dos;
pub mod ip_voter;
pub mod node;
pub mod proto;
pub mod routing;
pub mod sample;
pub mod state;
pub mod storage;
pub mod updater;

pub use bep42::{generate_secure_node_id, is_exempt_from_node_id_check, verify_secure_node_id};
pub use ip_voter::IpVoter;
pub use node::{
    bind_udp_v6_only, spawn, spawn_dual, spawn_dual_with_options, spawn_with_options,
    spawn_with_transports, DhtError, DhtHandle, DhtOptions, IterativePeersResult,
};
pub use proto::{GetItem, GetPeersResult, NodeId, NodeInfo, NodeInfoV6, PutArgs};
pub use routing::{Node, NodeV6, RoutingTable, RoutingTableV6};
pub use sample::{
    decode_dht_scrape_response, decode_sample_infohashes_response, encode_dht_scrape_response,
    encode_sample_infohashes_response, DhtScrapeQuery, DhtScrapeResponse, SampleInfohashesQuery,
    SampleInfohashesResponse,
};
pub use state::DhtState;
pub use storage::{DhtItem, DhtStorage, StorageError};
pub use updater::TorrentUpdatePointer;
