#[derive(Debug, Clone)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
}

/// The account `uid` belongs to; `None` for a uid with no passwd entry.
pub fn by_uid(uid: u32) -> Option<Account> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain data, for which all zeros is a valid value
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: pwd, buf and result outlive the call and buf.len() is buf's size; pwd's
    // string pointers into buf are never read
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(Account {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_user_has_an_account() {
        let me = by_uid(current_uid()).expect("current uid has a passwd entry");
        assert_eq!(me.uid, current_uid());
    }

    #[test]
    fn an_unused_uid_has_none() {
        assert!(by_uid(u32::MAX - 1).is_none());
    }
}
