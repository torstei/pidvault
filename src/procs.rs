use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

pub fn parent_of(pid: u32) -> Option<u32> {
    stat_field(pid, 1)
}

pub fn session_of(pid: u32) -> Option<u32> {
    stat_field(pid, 3)
}

fn stat_field(pid: u32, index: usize) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_after_comm(&stat, index)
}

pub fn real_uid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Field `index` counted from the state field, which follows `(comm)`.
fn parse_after_comm(stat: &str, index: usize) -> Option<u32> {
    // comm may itself contain ") ", so split after the last one
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(index)?.parse().ok()
}

/// A handle that keeps referring to the same process even after its pid is reused.
pub struct Pidfd(OwnedFd);

impl Pidfd {
    pub fn open(pid: u32) -> io::Result<Pidfd> {
        // SAFETY: pidfd_open takes only integers
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor pidfd_open just opened for this process, owned by nothing else
        Ok(Pidfd(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
    }
}

/// A pidfd for the process at the other end of `stream`, as it was when it connected; on
/// kernels before 6.5, which cannot give one, opened from its pid instead.
pub fn peer_pidfd(stream: &UnixStream, pid: u32) -> io::Result<Pidfd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd and len outlive the call and len is fd's size
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut fd).cast(),
            &mut len,
        )
    };
    if rc == 0 && fd >= 0 {
        // SAFETY: a descriptor the kernel just opened for this process, owned by nothing else
        return Ok(Pidfd(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    Pidfd::open(pid)
}

pub trait Liveness {
    fn has_exited(&self) -> bool;
}

impl Liveness for Pidfd {
    fn has_exited(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd outlives the call and the count is 1
        let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
        ready != 0
    }
}

pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
}

pub fn peer_cred(stream: &UnixStream) -> io::Result<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len outlive the call and len is cred's size
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred {
        pid: cred.pid as u32,
        uid: cred.uid,
    })
}

/// Keeps other processes out of this one's memory; refuses to continue if already traced.
pub fn harden() -> io::Result<()> {
    // also suppresses core dumps, which would hold decrypted vaults
    // SAFETY: PR_SET_DUMPABLE takes only integers
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // checked after PR_SET_DUMPABLE so no tracer can attach in between
    if tracer_pid()? != 0 {
        return Err(io::Error::other("refusing to run under a tracer"));
    }
    Ok(())
}

fn tracer_pid() -> io::Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| io::Error::other("no TracerPid in /proc/self/status"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_survives_hostile_comm() {
        assert_eq!(parse_after_comm("123 (a) b) S 77 123 124 0", 1), Some(77));
        assert_eq!(parse_after_comm("123 (a) b) S 77 123 124 0", 3), Some(124));
        assert_eq!(parse_after_comm("1 (systemd) S 0 1 1", 1), Some(0));
        assert_eq!(parse_after_comm("garbage", 1), None);
    }

    #[test]
    fn parent_of_self_is_real_parent() {
        let me = std::process::id();
        assert_eq!(parent_of(me), Some(std::os::unix::process::parent_id()));
    }

    #[test]
    fn pidfd_notices_exit() {
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let fd = Pidfd::open(child.id()).unwrap();
        assert!(!fd.has_exited());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(fd.has_exited());
    }
}
