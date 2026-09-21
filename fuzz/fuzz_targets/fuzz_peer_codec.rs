#![no_main]
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use synapse_wire::PeerCodec;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut codec = PeerCodec::new();
    let mut buf = BytesMut::from(data);
    let _ = codec.decode(&mut buf);
});
