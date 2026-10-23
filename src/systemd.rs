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
    let count: i32 = std::env::var("LISTEN_FDS")
        .context("no LISTEN_FDS")?
        .parse()?;
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let mut names = names.split(':');
    let fds = (FIRST_FD..FIRST_FD + count)
        .map(|fd| {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            let name = names.next().unwrap_or_default().to_owned();
            (name, unsafe { OwnedFd::from_raw_fd(fd) })
        })
        .collect();
    for var in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
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
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), fd.as_raw_fd());
    }
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
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    if unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) } != 1 {
        bail!("no file descriptor received");
    }
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            bail!("no file descriptor received");
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>());
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
}
