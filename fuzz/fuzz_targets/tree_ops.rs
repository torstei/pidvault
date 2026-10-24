//! Any sequence of file operations through the mount. A vault must always remain
//! savable, and a private key, once written, must never become readable: its bytes
//! may grow or be emptied, never changed.
#![no_main]

use std::collections::BTreeMap;
use std::ffi::OsStr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sshvault::keys::PLAIN_OPENSSH_KEY;
use sshvault::tree::{Kind, ROOT, Tree};

const NAMES: [&str; 4] = ["a", "b", "id", "keys"];

#[derive(Arbitrary, Debug)]
enum Op {
    Create {
        parent: u8,
        name: u8,
        mode: u16,
    },
    Mkdir {
        parent: u8,
        name: u8,
    },
    Copy {
        ino: u8,
        parent: u8,
        name: u8,
    },
    Unlink {
        parent: u8,
        name: u8,
    },
    Rmdir {
        parent: u8,
        name: u8,
    },
    Rename {
        parent: u8,
        name: u8,
        new_parent: u8,
        new_name: u8,
        no_replace: bool,
    },
    Write {
        ino: u8,
        offset: u16,
        bytes: Vec<u8>,
    },
    WriteKey {
        ino: u8,
        offset: u16,
    },
    Truncate {
        ino: u8,
        len: u16,
    },
    SetMode {
        ino: u8,
        mode: u16,
    },
}

fn data_of(tree: &Tree, ino: u64) -> Option<&[u8]> {
    match &tree.node(ino)?.kind {
        Kind::File { data, .. } => Some(data),
        Kind::Dir { .. } => None,
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut tree = Tree::empty();
    let mut inodes = vec![ROOT];
    let mut keys = BTreeMap::new();
    let pick = |inodes: &[u64], i: u8| inodes[i as usize % inodes.len()];
    let name = |i: u8| OsStr::new(NAMES[i as usize % NAMES.len()]);
    for op in ops.into_iter().take(64) {
        match op {
            Op::Create {
                parent,
                name: n,
                mode,
            } => {
                if let Ok(ino) = tree.create_file(pick(&inodes, parent), name(n), mode.into()) {
                    inodes.push(ino);
                }
            }
            Op::Mkdir { parent, name: n } => {
                if let Ok(ino) = tree.mkdir(pick(&inodes, parent), name(n)) {
                    inodes.push(ino);
                }
            }
            Op::Copy {
                ino,
                parent,
                name: n,
            } => {
                if let Ok(copy) = tree.copy_file(pick(&inodes, ino), pick(&inodes, parent), name(n))
                {
                    inodes.push(copy);
                }
            }
            Op::Unlink { parent, name: n } => {
                let _ = tree.unlink(pick(&inodes, parent), name(n));
            }
            Op::Rmdir { parent, name: n } => {
                let _ = tree.rmdir(pick(&inodes, parent), name(n));
            }
            Op::Rename {
                parent,
                name: n,
                new_parent,
                new_name,
                no_replace,
            } => {
                let _ = tree.rename(
                    pick(&inodes, parent),
                    name(n),
                    pick(&inodes, new_parent),
                    name(new_name),
                    no_replace,
                );
            }
            Op::Write { ino, offset, bytes } => {
                let _ = tree.write(pick(&inodes, ino), offset.into(), &bytes);
            }
            Op::WriteKey { ino, offset } => {
                let _ = tree.write(pick(&inodes, ino), offset.into(), PLAIN_OPENSSH_KEY);
            }
            Op::Truncate { ino, len } => {
                let _ = tree.truncate(pick(&inodes, ino), len.into());
            }
            Op::SetMode { ino, mode } => {
                let _ = tree.set_mode(pick(&inodes, ino), mode.into());
            }
        }
        keys.retain(|&ino, before: &mut Vec<u8>| match data_of(&tree, ino) {
            None | Some([]) => false,
            Some(now) => {
                assert!(tree.is_key(ino), "key {ino} became readable");
                assert!(
                    now.starts_with(before),
                    "key {ino} was changed, not appended to"
                );
                *before = now.to_vec();
                true
            }
        });
        for &ino in &inodes {
            if tree.is_key(ino) {
                keys.entry(ino)
                    .or_insert_with(|| data_of(&tree, ino).unwrap_or_default().to_vec());
            }
        }
    }
    let archive = tree.to_tar().expect("the vault can always be saved");
    let reopened = Tree::from_tar(&archive).expect("a saved vault opens again");
    assert_eq!(reopened.file_count(), tree.file_count());
});
