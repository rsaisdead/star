use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use oqs::kem::{Kem, SharedSecret};
use rand::{Rng, rng};

use crate::hash;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Key Exchange (Kyber1024)
pub fn key_exchange(kem: &Kem) -> Result<(Vec<u8>, SharedSecret), Box<dyn std::error::Error>> {
    // Server generates a key pair (public and private keys)
    let (server_public_key, _server_secret_key) = kem.keypair()?;

    // Client encapsulates a shared secret with the server's public key
    let (ciphertext, client_shared_secret) = kem.encapsulate(&server_public_key)?;

    // Serialize the ciphertext to Vec<u8> to simulate transmission
    let ciphertext_bytes: Vec<u8> = ciphertext.into_vec();

    Ok((ciphertext_bytes, client_shared_secret))
}

/// Encrypt data using AES256-CBC
pub fn encrypt_data(key: &[u8], plaintext: &mut [u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate a random IV (Initialization Vector)
    let ivgen: Vec<u8> = (0..16).map(|_| rng().random()).collect(); // 16 bytes IV
    let iv: &[u8] = &ivgen;

    let mut pt: Vec<u8> = Vec::with_capacity(plaintext.len() + 32);

    pt.extend_from_slice(plaintext);
    pt.extend_from_slice(&hash::sha3_256(&pt));

    let pt_len: usize = pt.len();

    // Encrypt the data
    let ciphertext: &[u8] = Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut pt, pt_len)
        .unwrap();

    Ok(ciphertext.to_vec())
}

/// Decrypt data using AES256-CBC with PKCS7 padding
pub fn decrypt_data(key: &[u8], iv: &[u8], ciphertext: &mut [u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Rewrite block in-place with plaintext data (Decrypt)
    let plaintext: &[u8] = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(ciphertext)
        .unwrap();

    Ok(plaintext.to_vec())
}
