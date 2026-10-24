//! What any process that can reach the agent socket sends it, up to the point where a
//! request would need an unlocked vault.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sshvault::agent::{parse_request, read_message};

fuzz_target!(|data: &[u8]| {
    let mut stream = data;
    while let Ok(Some(message)) = read_message(&mut stream) {
        let _ = parse_request(&message);
    }
});
