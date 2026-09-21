#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = synapse_dht::proto::Message::decode(data) {
        let _ = msg.encode();
    }
    if let Ok(bencode) = synapse_bencode::decode_buf(data) {
        if let Some(mut dict) = bencode.into_dict() {
            let mut dict2 = dict.clone();
            let _ = synapse_dht::decode_dht_scrape_response(&mut dict);
            let _ = synapse_dht::decode_sample_infohashes_response(&mut dict2);
        }
    }
});
