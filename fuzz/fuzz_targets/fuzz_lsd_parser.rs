#![no_main]

use libfuzzer_sys::fuzz_target;
use synapse_wire::lsd::parse_lsd_announce;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_lsd_announce(s);
    }
});
