//! A request line on the control socket, which every user can reach.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sshvault::protocol::Request;

fuzz_target!(|data: &[u8]| {
    let line = data.split(|&b| b == b'\n').next().unwrap_or_default();
    let _ = serde_json::from_slice::<Request>(line);
});
