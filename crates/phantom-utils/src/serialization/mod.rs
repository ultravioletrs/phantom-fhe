//! Serialization domain and version helpers.

use std::io::{Read, Write};

use crate::buffer::{BufferReader, BufferWriter};
use crate::{Result, UtilsError};

/// Fixed-width serialization domain separator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DomainTag([u8; 8]);

impl DomainTag {
    /// Creates a domain tag from exactly eight bytes.
    pub const fn from_array(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Creates a domain tag from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(UtilsError::InvalidDomainLength {
                actual: bytes.len(),
            });
        }

        let mut out = [0u8; 8];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// Returns this tag as bytes.
    pub const fn as_bytes(self) -> [u8; 8] {
        self.0
    }
}

/// Serialization format version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Version(u16);

impl Version {
    /// Creates a version value.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw version.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Common header for crate-owned binary serialization formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SerializationHeader {
    domain: DomainTag,
    version: Version,
}

impl SerializationHeader {
    /// Creates a new serialization header.
    pub const fn new(domain: DomainTag, version: Version) -> Self {
        Self { domain, version }
    }

    /// Returns the header domain.
    pub const fn domain(self) -> DomainTag {
        self.domain
    }

    /// Returns the header version.
    pub const fn version(self) -> Version {
        self.version
    }

    /// Writes the header to a binary writer.
    pub fn write_to<W: Write>(&self, writer: &mut BufferWriter<W>) -> Result<()> {
        writer.write_all(&self.domain.as_bytes())?;
        writer.write_u16_le(self.version.get())
    }

    /// Reads and validates a header from a binary reader.
    pub fn read_expected<R: Read>(
        reader: &mut BufferReader<R>,
        expected_domain: DomainTag,
        expected_version: Version,
    ) -> Result<Self> {
        let found_domain = DomainTag::from_array(reader.read_array()?);
        if found_domain != expected_domain {
            return Err(UtilsError::InvalidDomain {
                expected: expected_domain.as_bytes(),
                found: found_domain.as_bytes(),
            });
        }

        let found_version = Version::new(reader.read_u16_le()?);
        if found_version != expected_version {
            return Err(UtilsError::UnsupportedVersion {
                expected: expected_version.get(),
                found: found_version.get(),
            });
        }

        Ok(Self::new(found_domain, found_version))
    }
}
