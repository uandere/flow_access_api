use anyhow::anyhow;
use crate::flow::entities::{transaction, Transaction};
use crate::keys::hex_to_bytes;
use derive_more::From;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Sha3_256};
use crate::client::Error::DigestLenError;

#[derive(Debug, From)]
pub enum Error {
    #[from]
    KeysError(crate::keys::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for anyhow::Error {
    fn from(value: Error) -> Self {
        anyhow!(format!("{:?}", value))
    }
}


pub(crate) const TRANSACTION_DOMAIN_TAG: &str =
    "464c4f572d56302e302d7472616e73616374696f6e0000000000000000000000";

/// Calculate the hash of a transaction for signing using RLP encoding and SHA3-256
pub fn hash_transaction(tx: &Transaction) -> Result<Vec<u8>> {
    // Use SHA3-256 instead of SHA2-256
    let mut hasher = Sha3_256::new();

    // Add domain tag
    hasher.update(hex_to_bytes(TRANSACTION_DOMAIN_TAG)?);

    // Use RLP encoding to ensure canonical format
    let mut rlp: RlpStream = RlpStream::new_list(2);
    rlp.begin_list(9); // Transaction has 9 fields

    // 1. Script
    rlp.append(&tx.script);

    // 2. Arguments
    rlp.begin_list(tx.arguments.len());
    for arg in &tx.arguments {
        rlp.append(&arg.as_slice());
    }

    // 3. Reference Block ID
    rlp.append(&tx.reference_block_id);

    // 4. Gas Limit
    rlp.append(&tx.gas_limit);

    // 5. Proposal Key
    if let Some(pk) = &tx.proposal_key {
        // No need to begin a list here as per the fix
        rlp.append(&pk.address);
        rlp.append(&pk.key_id);
        rlp.append(&pk.sequence_number);
    } else {
        rlp.begin_list(0);
    }

    // 6. Payer
    rlp.append(&tx.payer);

    // 7. Authorizers
    rlp.begin_list(tx.authorizers.len());
    for auth in &tx.authorizers {
        rlp.append(&auth.as_slice());
    }

    // 8. Payload Signatures
    rlp.begin_list(tx.payload_signatures.len());
    for sig in &tx.payload_signatures {
        rlp.begin_list(3);
        rlp.append(&sig.address);
        rlp.append(&sig.key_id);
        rlp.append(&sig.signature);
    }

    // Finish RLP encoding
    let encoded = rlp.out();

    println!("RLP encoded: {}", hex::encode(encoded.clone()));

    // Hash the encoded transaction with SHA3-256
    hasher.update(&encoded);

    // Return the hash
    Ok(hasher.finalize().to_vec())
}

/// Sign a transaction with the given secp256k1 private key
pub fn sign_transaction(
    tx: &mut Transaction,
    signer_address: &[u8],
    key_index: u32,
    private_key: &SecretKey,
) -> crate::client::Result<()> {
    // Calculate the transaction hash
    let hash = hash_transaction(tx)?;

    // Create a Secp256k1 context
    let secp = Secp256k1::new();

    fn vec_to_array(vec: Vec<u8>) -> crate::client::Result<[u8; 32]> {
        vec.try_into().map_err(DigestLenError)
    }

    // Create a message from the hash
    let message = Message::from_digest(vec_to_array(hash.clone())?);

    println!("Message to sign: {}", hex::encode(&message[..]));

    // Sign the message
    let signature = secp.sign_ecdsa(&message, private_key);

    // Get the signature in compact format (64 bytes, R+S)
    let signature_bytes = signature.serialize_compact().to_vec();

    // Create a signature envelope
    let envelope_signature = transaction::Signature {
        address: signer_address.to_vec(),
        key_id: key_index,
        signature: signature_bytes,
    };

    // Add the signature to the envelope signatures
    tx.envelope_signatures.push(envelope_signature);

    Ok(())
}
