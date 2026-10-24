use std::io::{self, Read};
use std::ops::Deref;

use zeroize::Zeroize;

/// Largest decrypted vault the daemon will hold for one user.
pub const MAX_SECRET: usize = 4 * 1024 * 1024;

/// Bytes in their own anonymous mapping, locked out of swap, excluded from core
/// dumps, and wiped before the mapping is released.
pub struct SecretBuf {
    ptr: *mut u8,
    len: usize,
    mapped: usize,
}

// SAFETY: the mapping is owned exclusively and never aliased; shared access only reads
unsafe impl Send for SecretBuf {}
// SAFETY: as for Send; mutation needs &mut
unsafe impl Sync for SecretBuf {}

impl SecretBuf {
    pub fn with_capacity(capacity: usize) -> io::Result<SecretBuf> {
        if capacity > MAX_SECRET {
            return Err(io::Error::other(format!(
                "secret larger than {MAX_SECRET} bytes"
            )));
        }
        // SAFETY: sysconf has no preconditions
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mapped = capacity.max(1).div_ceil(page) * page;
        // SAFETY: a fresh anonymous mapping, which aliases nothing
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let buf = SecretBuf {
            ptr: ptr.cast(),
            len: 0,
            mapped,
        };
        // SAFETY: ptr..ptr+mapped is the mapping just made; buf's Drop unmaps it on error
        unsafe {
            if libc::mlock(ptr, mapped) != 0 {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(
                    err.kind(),
                    format!("cannot lock memory for decrypted data (raise RLIMIT_MEMLOCK): {err}"),
                ));
            }
            libc::madvise(ptr, mapped, libc::MADV_DONTDUMP);
        }
        Ok(buf)
    }

    pub fn from_reader(mut reader: impl Read, size_hint: usize) -> io::Result<SecretBuf> {
        let mut buf = SecretBuf::with_capacity(size_hint)?;
        let mut chunk = [0u8; 4096];
        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    chunk.zeroize();
                    return Err(e);
                }
            };
            let pushed = buf.extend_from_slice(&chunk[..n]);
            if let Err(e) = pushed {
                chunk.zeroize();
                return Err(e);
            }
        }
        chunk.zeroize();
        Ok(buf)
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_at(self.len, data)
    }

    /// Writes `data` at `offset`, growing the buffer; a gap reads as zeros.
    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        self.reserve(end)?;
        // SAFETY: reserve made end <= mapped, and data cannot overlap a mapping only self owns
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len()) };
        self.len = self.len.max(end);
        Ok(())
    }

    pub fn truncate(&mut self, len: usize) -> io::Result<()> {
        if len < self.len {
            // SAFETY: len..self.len lies within the mapping and is uniquely borrowed here
            unsafe { std::slice::from_raw_parts_mut(self.ptr.add(len), self.len - len) }.zeroize();
        } else {
            self.reserve(len)?;
        }
        self.len = len;
        Ok(())
    }

    pub fn try_clone(&self) -> io::Result<SecretBuf> {
        let mut copy = SecretBuf::with_capacity(self.len)?;
        copy.extend_from_slice(self)?;
        Ok(copy)
    }

    // Bytes past `len` are always zero: fresh mappings are, and truncate wipes what it drops.
    fn reserve(&mut self, needed: usize) -> io::Result<()> {
        if needed > self.mapped {
            let mut bigger =
                SecretBuf::with_capacity(needed.max((self.mapped * 2).min(MAX_SECRET)))?;
            // SAFETY: bigger's mapping is fresh and at least self.len long, self's is too
            unsafe { std::ptr::copy_nonoverlapping(self.ptr, bigger.ptr, self.len) };
            bigger.len = self.len;
            *self = bigger;
        }
        Ok(())
    }
}

impl io::Write for SecretBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(data)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the first len bytes of the mapping are initialised and live as long as self
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // SAFETY: the mapping is self's alone and is never touched again after this
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, self.mapped).zeroize();
            libc::munlock(self.ptr.cast(), self.mapped);
            libc::munmap(self.ptr.cast(), self.mapped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `Locked:` figure /proc reports for the mapping that starts at `addr`.
    fn locked_kb_of(addr: usize) -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let start = format!("{addr:x}-");
        smaps
            .lines()
            .skip_while(|l| !l.starts_with(&start))
            .find_map(|l| l.strip_prefix("Locked:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .expect("mapping not found in smaps")
    }

    #[test]
    fn grows_across_pages_and_keeps_contents() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let buf = SecretBuf::from_reader(&data[..], 16).unwrap();
        assert_eq!(&*buf, &data[..]);
    }

    #[test]
    fn memory_is_locked_while_held() {
        let buf = SecretBuf::with_capacity(64 * 1024).unwrap();
        assert_eq!(locked_kb_of(buf.ptr as usize), 64);
    }

    #[test]
    fn writes_at_offsets_and_truncates_with_zeroed_gaps() {
        let mut buf = SecretBuf::with_capacity(4).unwrap();
        buf.write_at(0, b"abcd").unwrap();
        buf.write_at(6000, b"z").unwrap();
        assert_eq!(buf.len(), 6001);
        assert!(buf[4..6000].iter().all(|&b| b == 0));
        buf.truncate(2).unwrap();
        assert_eq!(&*buf, b"ab");
        buf.truncate(5).unwrap();
        assert_eq!(&*buf, b"ab\0\0\0");
    }

    #[test]
    fn oversized_secrets_are_refused() {
        assert!(SecretBuf::with_capacity(MAX_SECRET + 1).is_err());
        let too_big = vec![0u8; MAX_SECRET + 1];
        assert!(SecretBuf::from_reader(&too_big[..], 0).is_err());
    }
}
