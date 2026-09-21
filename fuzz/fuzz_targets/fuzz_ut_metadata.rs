#![no_main]
use libfuzzer_sys::fuzz_target;
use synapse_wire::{ExtensionHandshake, UtMetadataMessage};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = UtMetadataMessage::decode(data) {
        let _ = msg.encode();
    }
    if let Ok(handshake) = ExtensionHandshake::decode(data) {
        let _ = handshake.encode();
    }
});
