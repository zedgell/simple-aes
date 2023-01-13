extern crate openssl;
extern crate rand;

use base64::DecodeError;
use openssl::error::ErrorStack;
use openssl::symm;
use rand::Rng;
use sha2::{Digest, Sha256};

pub fn encrypt<T, K>(data: T, key: K) -> Result<String, ErrorStack>
    where
        T: ToString,
        K: ToString,
{
    let cipher = symm::Cipher::aes_256_ctr();

    let iv: [u8; 16] = rand::thread_rng().gen();

    let mut hasher = Sha256::new();

    hasher.update(key.to_string().as_bytes());

    let result = hasher.finalize();

    let key = result.as_slice();

    let result = symm::encrypt(cipher, key, Some(&iv), data.to_string().as_bytes());

    match result {
        Ok(data) => Ok(base64::encode([&iv, data.as_slice()].concat())),
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub enum DecryptError {
    Base64Error(DecodeError),
    AESError(ErrorStack),
}

pub fn decrypt<T, K>(data: T, key: K) -> Result<String, DecryptError>
    where
        T: ToString,
        K: ToString,
{
    let decode_result = base64::decode(data.to_string());

    if let Err(err) = decode_result {
        return Err(DecryptError::Base64Error(err));
    }

    let full_encrypted_decoded = decode_result.unwrap();

    let iv: &[u8] = &full_encrypted_decoded[0..16];

    let data_encrypted: &[u8] = &full_encrypted_decoded[16..];

    let cipher = symm::Cipher::aes_256_ctr();

    let mut hasher = Sha256::new();

    hasher.update(key.to_string().as_bytes());

    let result = hasher.finalize();

    let key: &[u8] = result.as_slice();

    let decrypt_result: Result<Vec<u8>, ErrorStack> =
        symm::decrypt(cipher, key, Some(iv), data_encrypted);

    match decrypt_result {
        Ok(data) => Ok(String::from_utf8(data).unwrap()),
        Err(e) => Err(DecryptError::AESError(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_encrypts() {
        let encrypt = encrypt("12345abcdef", "my-super-secret-key");

        assert_eq!(encrypt.is_err(), false)
    }

    #[test]
    fn it_decrypts() {
        let encrypt = encrypt("12345abcdef", "my-super-secret-key").unwrap();

        let decrypt = decrypt(encrypt, "my-super-secret-key");

        assert_eq!(decrypt.is_err(), false);

        assert_eq!(decrypt.unwrap(), "12345abcdef".to_string())
    }
}
