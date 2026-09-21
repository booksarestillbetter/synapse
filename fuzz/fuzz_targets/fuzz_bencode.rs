#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bencode) = synapse_bencode::decode_buf(data) {
        let mut out = Vec::new();
        let _ = bencode.encode(&mut out);
    }
    let _ = synapse_bencode::decode_buf_first(data);
});
