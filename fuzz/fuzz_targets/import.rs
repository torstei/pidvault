//! What `import` hands the daemon: anyone can encrypt an archive of their choosing under
//! a passphrase they know, so after decryption it is still attacker-made. The stored vault
//! format is parsed here too.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pidvault::tree::Tree;
use pidvault::vault::{Stored, check_sealed};

fuzz_target!(|data: &[u8]| {
    let _ = check_sealed(data);
    let _ = Stored::parse(data);
    if let Ok(tree) = Tree::from_tar(data) {
        let archive = tree.to_tar().expect("an accepted tree can be saved");
        Tree::from_tar(&archive).expect("a saved tree can be opened again");
    }
});
