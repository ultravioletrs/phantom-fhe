//! Binary reader helpers.

use std::io::Read;

use crate::{Result, UtilsError};

/// Small wrapper around [`Read`] for deterministic little-endian primitives.
#[derive(Debug)]
pub struct BufferReader<R> {
    inner: R,
}

impl<R: Read> BufferReader<R> {
    /// Creates a new buffer reader.
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Returns the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Reads a single byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.inner.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16_le(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.inner.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.inner.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64_le(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.inner.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Reads exactly `N` bytes.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut buf = [0u8; N];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Reads a length-prefixed byte vector.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u64_le()?;
        let len = usize::try_from(len).map_err(|_| UtilsError::LengthOverflow { len })?;
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }
}
