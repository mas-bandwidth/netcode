use libsodium_sys;

use common::*;

pub const NETCODE_ENCRYPT_EXTA_BYTES: usize = libsodium_sys::crypto_aead_chacha20poly1305_ABYTES;

#[derive(Debug)]
pub enum EncryptError {
    InvalidPublicKeySize,
    BufferSizeMismatch,
    Failed
}

pub fn generate_key() -> [u8; NETCODE_KEY_BYTES] {
    let mut key: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];

    random_bytes(&mut key);

    key
}

pub fn random_bytes(out: &mut [u8]) {
    unsafe {
        libsodium_sys::randombytes_buf(out.as_mut_ptr(), out.len());
    }
}

pub fn encode(out: &mut [u8], data: &[u8], additional_data: Option<&[u8]>, nonce: u64, key: &[u8; NETCODE_KEY_BYTES]) -> Result<usize, EncryptError> {
    if key.len() != NETCODE_KEY_BYTES {
        return Err(EncryptError::InvalidPublicKeySize)
    }

    if out.len() < data.len() + NETCODE_ENCRYPT_EXTA_BYTES {
        return Err(EncryptError::BufferSizeMismatch)
    }

    let (result, written) = unsafe {
        let mut written: u64 = out.len() as u64;
        let result = libsodium_sys::crypto_aead_chacha20poly1305_encrypt(
                out.as_mut_ptr(),
                &mut written,
                data.as_ptr(),
                data.len() as u64,
                additional_data.map_or(::std::ptr::null_mut(), |v| v.as_ptr()),
                additional_data.map_or(0, |v| v.len()) as u64,
                ::std::ptr::null(),
                ::std::mem::transmute(&nonce),
                key);

        (result, written)
    };

    match result {
        -1 => Err(EncryptError::Failed),
        _ => Ok(written as usize)
    }
}

pub fn decode(out: &mut [u8], data: &[u8], additional_data: Option<&[u8]>, nonce: u64, key: &[u8; NETCODE_KEY_BYTES]) -> Result<usize, EncryptError> {
    if key.len() != NETCODE_KEY_BYTES {
        return Err(EncryptError::InvalidPublicKeySize)
    }

    if out.len() < data.len() - NETCODE_ENCRYPT_EXTA_BYTES {
        return Err(EncryptError::BufferSizeMismatch)
    }

    let (result, read) = unsafe {
        let mut read: u64 = out.len() as u64;
        let result = libsodium_sys::crypto_aead_chacha20poly1305_decrypt(
                out.as_mut_ptr(),
                &mut read,
                ::std::ptr::null_mut(),
                data.as_ptr(),
                data.len() as u64,
                additional_data.map_or(::std::ptr::null_mut(), |v| v.as_ptr()),
                additional_data.map_or(0, |v| v.len()) as u64,
                ::std::mem::transmute(&nonce),
                key);

        (result, read)
    };

    match result {
        -1 => Err(EncryptError::Failed),
        _ => Ok(read as usize)
    }
}