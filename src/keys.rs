use derive_more::From;
use secp256k1::SecretKey;


#[derive(Debug, From)]
pub enum Error {
    #[from]
    HexError(hex::FromHexError),
    #[from]
    Secp256k1Error(secp256k1::Error)
}

pub type Result<T> = std::result::Result<T, Error>;

/// Convert hex string to byte vector
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    let clean_hex = hex_str.trim_start_matches("0x");
    Ok(hex::decode(clean_hex)?)
}

/// Parse a secp256k1 private key from hex string
pub fn parse_private_key(private_key_hex: &str) -> Result<SecretKey> {
    let key_bytes = hex_to_bytes(private_key_hex)?;
    let secret_key = SecretKey::from_slice(&key_bytes)?;
    Ok(secret_key)
}
