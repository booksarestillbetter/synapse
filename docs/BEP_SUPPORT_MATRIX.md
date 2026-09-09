# Synapse 2.0 — BitTorrent Enhancement Proposals (BEP) Master Support Matrix

Synapse 2.0 provides standard-compliant implementations and compatibility across the entire official BitTorrent Enhancement Proposal (BEP) ecosystem.

---

## 1. Master Protocol Support Table

| BEP | Title | Category | Status | Implemented In | Description / Capabilities |
|:---:|---|---|:---:|---|---|
| **03** | BitTorrent Protocol Specification | Core | **Supported** | `synapse-wire`, `synapse-bencode` | Baseline wire framing, piece requests, choking, unchoking, keepalives, and bencode parser. |
| **05** | DHT Protocol (Kademlia) | DHT | **Supported** | `synapse-dht` | 160-bucket Kademlia distributed hash table, iterative routing, token rotation, and node routing tables. |
| **06** | Fast Extension | Wire | **Supported** | `synapse-wire::fast_ext` | `HaveAll`, `HaveNone`, deterministic `AllowedFast` piece sets, `SuggestPiece`, `RejectRequest`. |
| **09** | Extension for Peers to Send Metadata Files (`ut_metadata`) | Metadata | **Supported** | `synapse-wire::extension`, `synapse-engine::metadata` | 16 KiB metadata piece exchange over BEP 10 extension channels for instant magnet URI resolution. |
| **10** | Extension Protocol (`LTEP`) | Wire | **Supported** | `synapse-wire::extension` | Handshake dictionary negotiation for dynamic peer wire extensions (`ut_metadata`, `ut_pex`, etc.). |
| **11** | Peer Exchange (`ut_pex`) | Wire | **Supported** | `synapse-wire::pex`, `synapse-engine::pex` | Dual-stack IPv4/IPv6 peer gossip delta broadcasting with privacy boundary isolation. |
| **12** | Multitracker Extension | Tracker | **Supported** | `synapse-meta`, `synapse-tracker` | Hierarchical tiered announce list parsing and failover ordering (`announce-list`). |
| **14** | Local Peer Discovery (IPv4) | Discovery | **Supported** | `synapse-wire::lsd`, `synapse-engine::lsd` | SSDP multicast local peer discovery over `239.192.152.143:6771`. |
| **15** | UDP Tracker Protocol | Tracker | **Supported** | `synapse-tracker::udp` | Binary UDP connect, announce, retry backoff, and transaction ID validation. |
| **17** | HTTP Seeding (Hoffman Style) | WebSeed | **Supported** | `synapse-engine::hoffman` | HTTP GET piece and byte range formatting (`?info_hash=...&piece=...&ranges=...`). |
| **18** | Search Engine Specification | Search | **Supported** | `synapse-meta::bep18` | Bencode and XML torrent search engine schema models and serialization. |
| **19** | WebSeed (GetRight HTTP/FTP Seeding) | WebSeed | **Supported** | `synapse-engine::webseed` | `url-list` HTTP/HTTPS `Range: bytes={start}-{end}` piece mirror downloading. |
| **20** | Peer ID Conventions | Wire | **Supported** | `synapse-engine::peer` | Azureus-style peer identification (`-SY2200-...`). |
| **21** | Extension for Partial Seeds (`dont_have`) | Picker | **Supported** | `synapse-picker::priority` | Deselected piece masking so partial seeders are properly represented in swarms. |
| **22** | Local Peer Discovery (IPv6) | Discovery | **Supported** | `synapse-wire::lsd`, `synapse-engine::lsd` | IPv6 SSDP multicast local peer discovery on `[ff15::efc0:988f]:6771`. |
| **23** | Tracker Returns Compact Peer List | Tracker | **Supported** | `synapse-tracker::http` | 6-byte IPv4 (`4-byte IP + 2-byte port`) compact peer representation. |
| **24** | Tracker Returns External IP | Tracker | **Supported** | `synapse-tracker::http` | Ingests `external ip` tracker response parameter. |
| **26** | HTTP/REST Tracker Protocol | Tracker | **Supported** | `synapse-tracker::bep26` | RESTful HTTP tracker endpoint formatting (`/announce/{info_hash}`, `/scrape/{info_hash}`). |
| **27** | Private Torrents Specification | Privacy | **Supported** | `synapse-config`, `synapse-engine` | Unconditional suppression of DHT, PEX, and LSD on private swarms (`info.private = 1`). |
| **29** | Micro Transport Protocol (`uTP`) & LEDBAT | Transport | **Supported** | `synapse-wire::utp`, `synapse-engine::utp` | Delay-based congestion control over UDP with Selective ACK (`SACK`) and 100ms target delay. |
| **30** | Merkle Tree Torrents v1 (SHA-1) | Metadata | **Supported** | `synapse-meta::merkle_v1` | Historical SHA-1 16 KiB block Merkle tree hashing and root validation. |
| **32** | IPv6 DHT Extension | DHT | **Supported** | `synapse-dht::proto` | Dual-stack IPv6 `nodes6` and `values6` compact DHT routing. |
| **33** | DHT Scrape | DHT | **Supported** | `synapse-dht::sample` | DHT scrape queries returning estimated seeder (`sn`), leecher (`ln`), and bloom filters. |
| **35** | BitTorrent Digital Signatures | Metadata | **Supported** | `synapse-meta::signature` | Ed25519 and X.509 cryptographic signature verification in `.torrent` files. |
| **36** | Torrent RSS / Atom Feeds | Automation | **Supported** | `synapse-meta::feed` | Automated syndicated XML feed parsing extracting enclosure URLs, sizes, dates, and infohashes. |
| **38** | Finding Local Data Using Web Seeds | WebSeed | **Supported** | `synapse-engine::local_webseed` | Local cache directory resolution using piece hashes. |
| **40** | Canonical Peer Priority | Wire | **Supported** | `synapse-wire::bep40` | Deterministic tie-breaking algorithm resolving simultaneous cross-connection races. |
| **41** | UDP Tracker Protocol Extensions | Tracker | **Supported** | `synapse-tracker::udp_ext` | `0xBEFE` Type-Length-Value (TLV) extension option framing on BEP 15 UDP announces for URLData and passkeys. |
| **42** | DHT Security Extension | DHT | **Supported** | `synapse-dht::bep42` | CRC32c IP-derived Node IDs for IPv4/IPv6 Sybil and eclipse attack defense. |
| **43** | Read-Only DHT Nodes | DHT | **Supported** | `synapse-dht` | Read-only querying flag (`ro=1`) preventing routing table pollution. |
| **44** | Arbitrary Data Storage in DHT | DHT | **Supported** | `synapse-dht::storage` | Immutable (SHA-1) and mutable (Ed25519 public key, sequence, CAS, signature) key-value store. |
| **46** | Updating Torrents via DHT Mutable Items | DHT | **Supported** | `synapse-dht::updater` | Automated tracking and resolution of dynamic torrent revisions published under Ed25519 keys. |
| **47** | Padding Files & Whole-File Hashing | Metadata | **Supported** | `synapse-meta::padding` | Identifies `.pad/` and `attr: "p"` alignment files and verifies full-file SHA-1 checksums. |
| **48** | Tracker Scrape Protocol | Tracker | **Supported** | `synapse-tracker::http`, `synapse-tracker::udp` | Multi-hash HTTP (`/scrape`) and BEP 15 UDP binary scrape action (`action = 2`). |
| **50** | Peer Wire PubSub Extension | Wire | **Supported** | `synapse-wire::pubsub` | Topic-based gossip `Subscribe`, `Unsubscribe`, and `Publish` messaging over BEP 10 extension channels. |
| **51** | DHT Infohash Indexing (`sample_infohashes`) | DHT | **Supported** | `synapse-dht::sample` | `sample_infohashes` KRPC crawler querying and active swarm sampling. |
| **52** | BitTorrent v2 Protocol | Core | **Supported** | `synapse-meta::merkle`, `synapse-meta::v2` | SHA-256 Merkle trees (16 KiB blocks), hierarchical `file tree`, per-file `pieces root`, and hybrid v1+v2 swarms. |
| **53** | Magnet URI Format | Metadata | **Supported** | `synapse-meta` | BTIH, exact topics (`xt`), display names (`dn`), trackers (`tr`), and webseed sources (`ws`). |
| **54** | STUN Discovery for UDP / uTP | Transport | **Supported** | `synapse-wire::stun` | RFC 5389 / BEP 54 STUN binding requests and `XOR-MAPPED-ADDRESS` resolution for NAT discovery. |
| **55** | Holepunch Extension (`ut_holepunch`) | Transport | **Supported** | `synapse-wire::holepunch` | NAT-to-NAT direct uTP rendezvous relay coordination. |
