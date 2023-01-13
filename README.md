# simple-aes

-----

A simple AES256-ctr based off the [node-aes256 package](https://github.com/JamesMGreene/node-aes256#readme)

# Example

-------------

```rust
use simple_aes::{encypt, decrypt};

fn main() {
    // Key can be any length since it will be SHA256 hashed
    let encrypt = encrypt("12345abcdef", "my-super-secret-key").unwrap();

    let decrypt = decrypt(encrypt, "my-super-secret-key").unwrap();

    assert_eq!(decrypt, "12345abcdef".to_string())
}
```

# Flow

--------------

- Encryption:
  - Data and key is passed in.
  - Random 16 byte iv is created
  - Key is SHA256 hashed
  - Data is encrypted using the iv and the hash
  - The iv and the encrypted data are concatenated, base64 encoded and returned as a string
- Decryption
  - Key is SHA256 encrypted 
  - Encrypted data and key is passed in.
  - Data is base64 decoded to a ```Vec<u8>```.
  - First 16 elements in the Vec are grab for the iv.
  - Every element after the first 16 is passed into decryption along with key
  - The decrypted data is returned as a string
