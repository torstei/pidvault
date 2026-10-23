use std::ffi::{CStr, CString};
use std::io;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

pub fn by_uid(uid: u32) -> Option<Account> {
    lookup(|pwd, buf, result| unsafe {
        libc::getpwuid_r(uid, pwd, buf.as_mut_ptr(), buf.len(), result)
    })
}

pub fn by_name(name: &str) -> Option<Account> {
    let name = CString::new(name).ok()?;
    lookup(|pwd, buf, result| unsafe {
        libc::getpwnam_r(name.as_ptr(), pwd, buf.as_mut_ptr(), buf.len(), result)
    })
}

fn lookup(
    call: impl Fn(*mut libc::passwd, &mut [libc::c_char], *mut *mut libc::passwd) -> libc::c_int,
) -> Option<Account> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    if call(&mut pwd, &mut buf, &mut result) != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .ok()?
        .to_owned();
    Some(Account {
        name,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Irrevocably becomes `account`: supplementary groups, gid and uid, real and saved.
pub fn drop_privileges(account: &Account) -> Result<()> {
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(io::Error::last_os_error()).context("setgroups");
        }
        if libc::setresgid(account.gid, account.gid, account.gid) != 0 {
            return Err(io::Error::last_os_error()).context("setresgid");
        }
        if libc::setresuid(account.uid, account.uid, account.uid) != 0 {
            return Err(io::Error::last_os_error()).context("setresuid");
        }
        if libc::setuid(0) == 0 || libc::geteuid() != account.uid {
            bail!(
                "privileges could be regained after dropping to {}",
                account.name
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_round_trips() {
        let me = by_uid(current_uid()).expect("current uid has a passwd entry");
        assert_eq!(by_name(&me.name).unwrap().uid, me.uid);
    }

    #[test]
    fn unknown_name_is_none() {
        assert!(by_name("no-such-user-sshvault-test").is_none());
        assert!(by_name("nul\0byte").is_none());
    }
}
