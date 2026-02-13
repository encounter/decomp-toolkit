use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, KeyInit},
    Aes128Dec,
};
use anyhow::{anyhow, bail, Result};

/// AES-128-CBC decrypt with zero IV and no padding.
///
/// * `key`        – 16 bytes AES key
/// * `ciphertext` – length must be multiple of 16 bytes
///
/// Returns decrypted plaintext bytes or error if input length invalid.
pub fn decrypt_aes128_cbc_no_padding(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() % 16 != 0 {
        bail!("ciphertext length must be a multiple of 16 bytes");
    }

    let cipher = Aes128Dec::new_from_slice(key).map_err(|_| anyhow!("invalid key"))?;

    let mut prev_block = [0u8; 16]; // zero IV
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for ct_block in ciphertext.chunks_exact(16) {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(ct_block);
        cipher.decrypt_block(&mut block);

        // CBC: XOR decrypted block with previous ciphertext (or IV for first block)
        for (b, p) in block.iter_mut().zip(&prev_block) {
            *b ^= *p;
        }

        plaintext.extend_from_slice(&block);
        prev_block.copy_from_slice(ct_block);
    }

    Ok(plaintext)
}
