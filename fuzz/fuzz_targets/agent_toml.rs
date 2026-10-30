//! A vault's agent.toml, which decides which keys a forwarded connection may use.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pidvault::agent::Policy;

fuzz_target!(|data: &[u8]| {
    let _ = Policy::parse(data);
});
