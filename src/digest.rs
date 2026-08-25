use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::{Digest, Sha1};

pub fn hmac_md5_digest(input: impl AsRef<[u8]>) -> String {
    let mut hasher = Hmac::<Md5>::new_from_slice(&[]).unwrap();
    hasher.update(input.as_ref());
    hasher
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn sha1_digest(input: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}
