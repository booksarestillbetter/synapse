#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use synapse_wire::utp::UtpPacket;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    if let Ok(pkt) = UtpPacket::decode(bytes) {
        let _ = pkt.encode();
    }
});
