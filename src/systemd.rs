use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail};

const FIRST_FD: i32 = 3;

/// The file descriptors systemd passed to this process, with their names.
pub fn listen_fds() -> Result<Vec<(String, OwnedFd)>> {
    let pid: u32 = std::env::var("LISTEN_PID")
        .context("not started by systemd: no LISTEN_PID")?
        .parse()?;
    if pid != std::process::id() {
        bail!("LISTEN_PID is for another process");
    }
    let count: u8 = std::env::var("LISTEN_FDS")
        .context("no LISTEN_FDS")?
        .parse()
        .context("LISTEN_FDS is not a small count")?;
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let mut names = names.split(':');
    let mut fds = Vec::new();
    for fd in FIRST_FD..FIRST_FD + i32::from(count) {
        // SAFETY: fcntl on any integer is sound; it fails with EBADF if fd is not open
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            bail!("LISTEN_FDS names fd {fd}, which is not open");
        }
        let name = names.next().unwrap_or_default().to_owned();
        // SAFETY: fd is open, and systemd handed it to this process (LISTEN_PID) for it
        // alone; nothing else in the process refers to it
        fds.push((name, unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    for var in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        // SAFETY: called while the process is still single-threaded, before the daemon
        // or the mount helper starts any thread, so nothing reads the environment meanwhile
        unsafe { std::env::remove_var(var) };
    }
    Ok(fds)
}

const FD_SPACE: usize = 64;

pub fn send_fd(stream: &UnixStream, fd: &OwnedFd) -> Result<()> {
    let byte = [0u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut control = [0u8; FD_SPACE];
    // SAFETY: msghdr is plain data, for which all zeros is a valid value
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE only computes a size
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as _;
    // SAFETY: msg_control points at FD_SPACE bytes, more than the CMSG_SPACE for one int
    // set as msg_controllen, so CMSG_FIRSTHDR is non-null and the header and its data fit
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), fd.as_raw_fd());
    }
    // SAFETY: msg and every buffer it points at outlive the call
    if unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) } != 1 {
        return Err(io::Error::last_os_error()).context("passing a file descriptor");
    }
    Ok(())
}

pub fn recv_fd(stream: &UnixStream) -> Result<OwnedFd> {
    let mut byte = [0u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0u8; FD_SPACE];
    // SAFETY: msghdr is plain data, for which all zeros is a valid value
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    // SAFETY: msg and every buffer it points at outlive the call, and msg_controllen is
    // the size of the control buffer, so the kernel writes only within it
    if unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) } != 1 {
        bail!("no file descriptor received");
    }
    let one_fd = || {
        // SAFETY: CMSG_LEN only computes a size
        (unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) }) as usize
    };
    // SAFETY: the kernel filled in msg; CMSG_FIRSTHDR returns null or a header lying
    // within msg_controllen, and cmsg_len is checked before its data is read
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len as usize != one_fd()
            || msg.msg_flags & libc::MSG_CTRUNC != 0
        {
            bail!("expected exactly one file descriptor");
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>());
        // the kernel installed fd in this process for this message alone
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};

    #[test]
    fn a_file_descriptor_crosses_a_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"passed").unwrap();
        send_fd(&a, &OwnedFd::from(file)).unwrap();
        let mut received = std::fs::File::from(recv_fd(&b).unwrap());
        received.rewind().unwrap();
        let mut text = String::new();
        received.read_to_string(&mut text).unwrap();
        assert_eq!(text, "passed");
    }

    #[test]
    fn a_message_without_a_file_descriptor_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        (&a).write_all(b"x").unwrap();
        assert!(recv_fd(&b).is_err());
    }
}
