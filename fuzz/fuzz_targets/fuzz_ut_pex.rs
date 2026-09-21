#![no_main]
use libfuzzer_sys::fuzz_target;
use synapse_wire::UtPexMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = UtPexMessage::decode(data) {
        let _ = msg.encode();
    }
});
