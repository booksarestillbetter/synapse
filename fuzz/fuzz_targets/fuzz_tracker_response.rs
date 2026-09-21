#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. HTTP Tracker announce response bencode decoding
    let _ = synapse_tracker::http::parse_response(data);

    // 2. HTTP Tracker scrape response bencode decoding
    let _ = synapse_tracker::http::parse_scrape_response(data);

    // 3. UDP Tracker connect response decoding
    let _ = synapse_tracker::udp::parse_connect_response(data);

    // 4. UDP Tracker announce response decoding
    let _ = synapse_tracker::udp::parse_announce_response(data);

    // 5. UDP Tracker scrape response decoding
    let hashes = [[0x42u8; 20], [0x11u8; 20]];
    let _ = synapse_tracker::udp::parse_scrape_response(data, &hashes);

    // 6. BEP 41 UDP tracker options decoding
    let _ = synapse_tracker::decode_udp_options(data);
});
