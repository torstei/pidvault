use std::io::{self, Read};
use std::ops::Deref;

use zeroize::Zeroize;

/// Largest decrypted vault the daemon will hold for one user.
pub const MAX_SECRET: usize = 4 * 1024 * 1024;

/// Bytes that are wiped when dropped, and whose storage is wiped before it is given up
/// for a larger one, so no copy is left behind. Swap and core dumps are kept away from
/// the whole daemon (MemorySwapMax=0, PR_SET_DUMPABLE) rather than buffer by buffer.
pub struct SecretBuf {
    data: Vec<u8>,
}

impl SecretBuf {
    pub fn with_capacity(capacity: usize) -> io::Result<SecretBuf> {
        if capacity > MAX_SECRET {
            return Err(io::Error::other(format!(
                "secret larger than {MAX_SECRET} bytes"
            )));
        }
        Ok(SecretBuf {
            data: Vec::with_capacity(capacity),
        })
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
        self.write_at(self.data.len(), data)
    }

    /// Writes `data` at `offset`, growing the buffer; a gap reads as zeros.
    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        if end > self.data.len() {
            self.reserve(end)?;
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(data);
        Ok(())
    }

    pub fn truncate(&mut self, len: usize) -> io::Result<()> {
        if len < self.data.len() {
            self.data[len..].zeroize();
            self.data.truncate(len);
        } else {
            self.reserve(len)?;
            self.data.resize(len, 0);
        }
        Ok(())
    }

    pub fn try_clone(&self) -> io::Result<SecretBuf> {
        let mut copy = SecretBuf::with_capacity(self.data.len())?;
        copy.extend_from_slice(self)?;
        Ok(copy)
    }

    // never lets the Vec reallocate by itself, which would leave the old storage unwiped
    fn reserve(&mut self, needed: usize) -> io::Result<()> {
        if needed > self.data.capacity() {
            let mut bigger =
                SecretBuf::with_capacity(needed.max((self.data.capacity() * 2).min(MAX_SECRET)))?;
            bigger.data.extend_from_slice(&self.data);
            std::mem::swap(self, &mut bigger);
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
        &self.data
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_across_pages_and_keeps_contents() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let buf = SecretBuf::from_reader(&data[..], 16).unwrap();
        assert_eq!(&*buf, &data[..]);
    }

    #[test]
    fn growth_doubles_the_storage() {
        let mut buf = SecretBuf::with_capacity(4).unwrap();
        buf.extend_from_slice(b"abcd").unwrap();
        buf.extend_from_slice(b"e").unwrap();
        assert_eq!(&*buf, b"abcde");
        assert_eq!(buf.data.capacity(), 8);
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
