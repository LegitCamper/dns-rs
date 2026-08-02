//! Fixed-size inline representation of a DNS name, used as a hash-map key
//! component wherever a name needs to be looked up without allocating a
//! `String` for the lookup itself (the response cache and the in-flight
//! dedup registry both key on `(RecordType, DNSClass, name)`).

use std::hash::{Hash, Hasher};

/// RFC 1035 wire-format name length limit; names are stored inline
/// (fixed-size array) so a lookup never has to allocate a `String`.
pub(crate) const MAX_NAME_LEN: usize = 255;

#[derive(Clone, Copy)]
pub(crate) struct InlineName {
    len: u8,
    bytes: [u8; MAX_NAME_LEN],
}

impl InlineName {
    pub(crate) fn new(name: &str) -> Option<Self> {
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self { len: name.len() as u8, bytes })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// For logging only; never relied on for correctness.
    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).unwrap_or("<invalid-utf8>")
    }
}

impl PartialEq for InlineName {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for InlineName {}

impl Hash for InlineName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}
