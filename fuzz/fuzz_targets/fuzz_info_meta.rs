#![no_main]
use libfuzzer_sys::fuzz_target;
use synapse_meta::Info;

fuzz_target!(|data: &[u8]| {
    if let Ok(bencode) = synapse_bencode::decode_buf(data) {
        let _ = Info::from_bencode(bencode);
    }
    let _ = Info::from_info_dict_bytes(data);
});
