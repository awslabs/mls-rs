#[derive(Clone)]
pub enum MessageDigest {
    Sha256,
    Sha512
}

impl MessageDigest {
    pub(crate) fn len(&self) -> u8 {
        match self {
            MessageDigest::Sha256 => 32,
            MessageDigest::Sha512 => 64
        }
    }
}

impl Into<openssl::hash::MessageDigest> for MessageDigest {
    fn into(self) -> openssl::hash::MessageDigest {
        match self {
            MessageDigest::Sha256 => openssl::hash::MessageDigest::sha256(),
            MessageDigest::Sha512 => openssl::hash::MessageDigest::sha512()
        }
    }
}