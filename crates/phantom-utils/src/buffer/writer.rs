//! Binary writer helpers.

use std::io::Write;

use crate::Result;

/// Small wrapper around [`Write`] for deterministic little-endian primitives.
#[derive(Debug)]
pub struct BufferWriter<W> {
    inner: W,
}

impl<W: Write> BufferWriter<W> {
    /// Creates a new buffer writer.
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Returns the wrapped writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Writes a single byte.
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.inner.write_all(&[value])?;
        Ok(())
    }

    /// Writes a little-endian `u16`.
    pub fn write_u16_le(&mut self, value: u16) -> Result<()> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    /// Writes a little-endian `u32`.
    pub fn write_u32_le(&mut self, value: u32) -> Result<()> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64_le(&mut self, value: u64) -> Result<()> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    /// Writes raw bytes without a length prefix.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.inner.write_all(bytes)?;
        Ok(())
    }

    /// Writes a `u64` length prefix followed by raw bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_u64_le(bytes.len() as u64)?;
        self.write_all(bytes)
    }
}
