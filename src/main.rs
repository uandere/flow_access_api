use futures::StreamExt;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Sha3_256 as Sha256};
use std::time::Duration;
use tokio::select;
use tonic::{Request, transport::Channel};
use serde_json;
use serde::{Deserialize, Serialize, Deserializer};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;
use std::collections::HashMap;

// Import the generated Flow protobuf modules
extern crate prost_types;

mod flow {
    pub mod access {
        tonic::include_proto!("flow.access");
    }

    pub mod entities {
        tonic::include_proto!("flow.entities");
    }

    pub mod execution {
        tonic::include_proto!("flow.execution");
    }

    pub mod executiondata {
        tonic::include_proto!("flow.executiondata");
    }
}

use flow::access::access_api_client::AccessApiClient as AccessClient;
use flow::access::{
    GetAccountRequest, GetLatestBlockRequest, SendAndSubscribeTransactionStatusesRequest,
    ExecuteScriptAtLatestBlockRequest, GetEventsForHeightRangeRequest,
};
use flow::entities::{Transaction, transaction, Event};

// Define Cadence-JSON format deserializers
#[derive(Debug, Deserialize)]
struct CadenceValue<T> {
    #[serde(rename = "type")]
    value_type: String,
    value: T,
}

#[derive(Debug)]
enum CadenceType {
    Void,
    Optional(Box<CadenceType>),
    Bool(bool),
    String(String),
    Address(String),
    Int(String),
    UInt(String),
    Int8(String),
    UInt8(String),
    Int16(String),
    UInt16(String),
    Int32(String),
    UInt32(String),
    Int64(String),
    UInt64(String),
    Int128(String),
    UInt128(String),
    Int256(String),
    UInt256(String),
    Word8(String),
    Word16(String),
    Word32(String),
    Word64(String),
    Word128(String),
    Word256(String),
    Fix64(String),
    UFix64(String),
    Array(Vec<CadenceType>),
    Dictionary(Vec<(CadenceType, CadenceType)>),
    Struct(String, Vec<(String, CadenceType)>),
    Resource(String, Vec<(String, CadenceType)>),
    Event(String, Vec<(String, CadenceType)>),
    Contract(String, Vec<(String, CadenceType)>),
    Enum(String, Vec<(String, CadenceType)>),
    Path(String, String),
    Type(Box<CadenceType>),
    Capability(u64, String, Box<CadenceType>),
    Function(String),
}

impl<'de> Deserialize<'de> for CadenceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CadenceTypeVisitor;

        impl<'de> Visitor<'de> for CadenceTypeVisitor {
            type Value = CadenceType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid Cadence-JSON value")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CadenceType, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut cadence_type: Option<String> = None;
                let mut value: Option<serde_json::Value> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            cadence_type = Some(map.next_value()?);
                        }
                        "value" => {
                            value = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(&key, &["type", "value"]));
                        }
                    }
                }

                let cadence_type = cadence_type.ok_or_else(|| de::Error::missing_field("type"))?;

                match cadence_type.as_str() {
                    "Void" => Ok(CadenceType::Void),
                    "Bool" => {
                        if let Some(value) = value {
                            if let Some(bool_value) = value.as_bool() {
                                return Ok(CadenceType::Bool(bool_value));
                            }
                        }
                        Err(de::Error::custom("Expected bool value for Bool type"))
                    }
                    "String" => {
                        if let Some(value) = value {
                            if let Some(string_value) = value.as_str() {
                                return Ok(CadenceType::String(string_value.to_string()));
                            }
                        }
                        Err(de::Error::custom("Expected string value for String type"))
                    }
                    "Array" => {
                        if let Some(value) = value {
                            if let Some(array_value) = value.as_array() {
                                let mut items = Vec::new();
                                for item in array_value {
                                    let value_json = serde_json::json!({
                                        "type": item.get("type").ok_or_else(|| de::Error::missing_field("type"))?,
                                        "value": item.get("value").ok_or_else(|| de::Error::missing_field("value"))?
                                    });
                                    let item_value: CadenceType = serde_json::from_value(value_json)
                                        .map_err(|e| de::Error::custom(format!("Error parsing array item: {}", e)))?;
                                    items.push(item_value);
                                }
                                return Ok(CadenceType::Array(items));
                            }
                        }
                        Err(de::Error::custom("Expected array value for Array type"))
                    }
                    "Optional" => {
                        if let Some(value) = value {
                            if value.is_null() {
                                return Ok(CadenceType::Optional(Box::new(CadenceType::Void)));
                            } else {
                                let value_json = serde_json::json!({
                                    "type": value.get("type").ok_or_else(|| de::Error::missing_field("type"))?,
                                    "value": value.get("value").ok_or_else(|| de::Error::missing_field("value"))?
                                });
                                let inner_value: CadenceType = serde_json::from_value(value_json)
                                    .map_err(|e| de::Error::custom(format!("Error parsing optional value: {}", e)))?;
                                return Ok(CadenceType::Optional(Box::new(inner_value)));
                            }
                        }
                        Err(de::Error::custom("Expected value or null for Optional type"))
                    }
                    "Dictionary" => {
                        if let Some(value) = value {
                            if let Some(dict_entries) = value.as_array() {
                                let mut entries = Vec::new();
                                for entry in dict_entries {
                                    let key_json = serde_json::json!({
                                        "type": entry.get("key").and_then(|k| k.get("type")).ok_or_else(|| de::Error::missing_field("key.type"))?,
                                        "value": entry.get("key").and_then(|k| k.get("value")).ok_or_else(|| de::Error::missing_field("key.value"))?
                                    });
                                    let key: CadenceType = serde_json::from_value(key_json)
                                        .map_err(|e| de::Error::custom(format!("Error parsing dictionary key: {}", e)))?;

                                    let val_json = serde_json::json!({
                                        "type": entry.get("value").and_then(|v| v.get("type")).ok_or_else(|| de::Error::missing_field("value.type"))?,
                                        "value": entry.get("value").and_then(|v| v.get("value")).ok_or_else(|| de::Error::missing_field("value.value"))?
                                    });
                                    let val: CadenceType = serde_json::from_value(val_json)
                                        .map_err(|e| de::Error::custom(format!("Error parsing dictionary value: {}", e)))?;

                                    entries.push((key, val));
                                }
                                return Ok(CadenceType::Dictionary(entries));
                            }
                        }
                        Err(de::Error::custom("Expected array value for Dictionary type"))
                    }
                    // Handle numeric types
                    "Int" | "UInt" | "Int8" | "UInt8" | "Int16" | "UInt16" | "Int32" | "UInt32" |
                    "Int64" | "UInt64" | "Int128" | "UInt128" | "Int256" | "UInt256" |
                    "Word8" | "Word16" | "Word32" | "Word64" | "Word128" | "Word256" => {
                        if let Some(value) = value {
                            if let Some(num_str) = value.as_str() {
                                return match cadence_type.as_str() {
                                    "Int" => Ok(CadenceType::Int(num_str.to_string())),
                                    "UInt" => Ok(CadenceType::UInt(num_str.to_string())),
                                    "Int8" => Ok(CadenceType::Int8(num_str.to_string())),
                                    "UInt8" => Ok(CadenceType::UInt8(num_str.to_string())),
                                    "Int16" => Ok(CadenceType::Int16(num_str.to_string())),
                                    "UInt16" => Ok(CadenceType::UInt16(num_str.to_string())),
                                    "Int32" => Ok(CadenceType::Int32(num_str.to_string())),
                                    "UInt32" => Ok(CadenceType::UInt32(num_str.to_string())),
                                    "Int64" => Ok(CadenceType::Int64(num_str.to_string())),
                                    "UInt64" => Ok(CadenceType::UInt64(num_str.to_string())),
                                    "Int128" => Ok(CadenceType::Int128(num_str.to_string())),
                                    "UInt128" => Ok(CadenceType::UInt128(num_str.to_string())),
                                    "Int256" => Ok(CadenceType::Int256(num_str.to_string())),
                                    "UInt256" => Ok(CadenceType::UInt256(num_str.to_string())),
                                    "Word8" => Ok(CadenceType::Word8(num_str.to_string())),
                                    "Word16" => Ok(CadenceType::Word16(num_str.to_string())),
                                    "Word32" => Ok(CadenceType::Word32(num_str.to_string())),
                                    "Word64" => Ok(CadenceType::Word64(num_str.to_string())),
                                    "Word128" => Ok(CadenceType::Word128(num_str.to_string())),
                                    "Word256" => Ok(CadenceType::Word256(num_str.to_string())),
                                    _ => Err(de::Error::custom(format!("Unexpected numeric type: {}", cadence_type))),
                                };
                            }
                        }
                        Err(de::Error::custom(format!("Expected string value for {} type", cadence_type)))
                    }
                    // Fixed point numbers
                    "Fix64" | "UFix64" => {
                        if let Some(value) = value {
                            if let Some(num_str) = value.as_str() {
                                return match cadence_type.as_str() {
                                    "Fix64" => Ok(CadenceType::Fix64(num_str.to_string())),
                                    "UFix64" => Ok(CadenceType::UFix64(num_str.to_string())),
                                    _ => Err(de::Error::custom(format!("Unexpected fixed point type: {}", cadence_type))),
                                };
                            }
                        }
                        Err(de::Error::custom(format!("Expected string value for {} type", cadence_type)))
                    }
                    // Address
                    "Address" => {
                        if let Some(value) = value {
                            if let Some(addr_str) = value.as_str() {
                                return Ok(CadenceType::Address(addr_str.to_string()));
                            }
                        }
                        Err(de::Error::custom("Expected string value for Address type"))
                    }
                    // Composites
                    "Struct" | "Resource" | "Event" | "Contract" | "Enum" => {
                        if let Some(value) = value {
                            if let Some(obj) = value.as_object() {
                                let id = obj.get("id")
                                    .and_then(|id| id.as_str())
                                    .ok_or_else(|| de::Error::missing_field("id"))?
                                    .to_string();

                                let fields = obj.get("fields")
                                    .and_then(|fields| fields.as_array())
                                    .ok_or_else(|| de::Error::missing_field("fields"))?;

                                let mut field_values = Vec::new();
                                for field in fields {
                                    let name = field.get("name")
                                        .and_then(|name| name.as_str())
                                        .ok_or_else(|| de::Error::missing_field("name"))?
                                        .to_string();

                                    let field_value = field.get("value")
                                        .ok_or_else(|| de::Error::missing_field("value"))?;

                                    let field_type = field_value.get("type")
                                        .and_then(|t| t.as_str())
                                        .ok_or_else(|| de::Error::missing_field("type"))?
                                        .to_string();

                                    let field_val = field_value.get("value")
                                        .ok_or_else(|| de::Error::missing_field("value"))?;

                                    let value_json = serde_json::json!({
                                        "type": field_type,
                                        "value": field_val
                                    });

                                    let parsed_value: CadenceType = serde_json::from_value(value_json)
                                        .map_err(|e| de::Error::custom(format!("Error parsing field value: {}", e)))?;

                                    field_values.push((name, parsed_value));
                                }

                                return match cadence_type.as_str() {
                                    "Struct" => Ok(CadenceType::Struct(id, field_values)),
                                    "Resource" => Ok(CadenceType::Resource(id, field_values)),
                                    "Event" => Ok(CadenceType::Event(id, field_values)),
                                    "Contract" => Ok(CadenceType::Contract(id, field_values)),
                                    "Enum" => Ok(CadenceType::Enum(id, field_values)),
                                    _ => Err(de::Error::custom(format!("Unexpected composite type: {}", cadence_type))),
                                };
                            }
                        }
                        Err(de::Error::custom(format!("Expected object value for {} type", cadence_type)))
                    }
                    // Path
                    "Path" => {
                        if let Some(value) = value {
                            if let Some(obj) = value.as_object() {
                                let domain = obj.get("domain")
                                    .and_then(|domain| domain.as_str())
                                    .ok_or_else(|| de::Error::missing_field("domain"))?
                                    .to_string();

                                let identifier = obj.get("identifier")
                                    .and_then(|id| id.as_str())
                                    .ok_or_else(|| de::Error::missing_field("identifier"))?
                                    .to_string();

                                return Ok(CadenceType::Path(domain, identifier));
                            }
                        }
                        Err(de::Error::custom("Expected object value for Path type"))
                    }
                    // Type
                    "Type" => {
                        if let Some(value) = value {
                            if let Some(obj) = value.as_object() {
                                if let Some(static_type) = obj.get("staticType") {
                                    // For simplicity, we just store the type info as a string
                                    return Ok(CadenceType::Type(Box::new(CadenceType::String(
                                        static_type.to_string()
                                    ))));
                                }
                            }
                        }
                        Err(de::Error::custom("Expected object value for Type type"))
                    }
                    // Capability
                    "Capability" => {
                        if let Some(value) = value {
                            if let Some(obj) = value.as_object() {
                                let id_str = obj.get("id")
                                    .and_then(|id| id.as_str())
                                    .ok_or_else(|| de::Error::missing_field("id"))?;

                                let id = id_str.parse::<u64>()
                                    .map_err(|_| de::Error::custom(format!("Invalid id value: {}", id_str)))?;

                                let address = obj.get("address")
                                    .and_then(|addr| addr.as_str())
                                    .ok_or_else(|| de::Error::missing_field("address"))?
                                    .to_string();

                                // For simplicity, we just store borrow type as a string
                                let borrow_type = obj.get("borrowType")
                                    .ok_or_else(|| de::Error::missing_field("borrowType"))?;

                                return Ok(CadenceType::Capability(
                                    id,
                                    address,
                                    Box::new(CadenceType::String(borrow_type.to_string()))
                                ));
                            }
                        }
                        Err(de::Error::custom("Expected object value for Capability type"))
                    }
                    // Function
                    "Function" => {
                        if let Some(value) = value {
                            if let Some(obj) = value.as_object() {
                                if let Some(func_type) = obj.get("functionType") {
                                    // For simplicity, we just store the function type info as a string
                                    return Ok(CadenceType::Function(func_type.to_string()));
                                }
                            }
                        }
                        Err(de::Error::custom("Expected object value for Function type"))
                    }
                    _ => Err(de::Error::custom(format!("Unsupported Cadence type: {}", cadence_type))),
                }
            }
        }

        deserializer.deserialize_map(CadenceTypeVisitor)
    }
}

// Helper function to extract string values from CadenceType
fn extract_string_from_cadence(cadence_value: &CadenceType) -> Option<String> {
    match cadence_value {
        CadenceType::String(s) => Some(s.clone()),
        _ => None,
    }
}

// Helper function to extract CadenceType::Array values as Vec<String>
fn extract_strings_from_cadence_array(cadence_value: &CadenceType) -> Vec<String> {
    match cadence_value {
        CadenceType::Array(items) => {
            items.iter()
                .filter_map(|item| extract_string_from_cadence(item))
                .collect()
        }
        _ => Vec::new(),
    }
}

// Helper to extract dictionary entries as HashMap<String, i64>
fn extract_string_int_map_from_cadence(cadence_value: &CadenceType) -> HashMap<String, i64> {
    let mut result = HashMap::new();

    if let CadenceType::Dictionary(entries) = cadence_value {
        for (key, value) in entries {
            if let (Some(k), Some(v)) = (extract_string_from_cadence(key), extract_int_from_cadence(value)) {
                result.insert(k, v);
            }
        }
    }

    result
}

// Helper function to extract integer values from CadenceType
fn extract_int_from_cadence(cadence_value: &CadenceType) -> Option<i64> {
    match cadence_value {
        CadenceType::Int(s) | CadenceType::Int8(s) | CadenceType::Int16(s) |
        CadenceType::Int32(s) | CadenceType::Int64(s) => {
            s.parse::<i64>().ok()
        },
        CadenceType::UInt(s) | CadenceType::UInt8(s) | CadenceType::UInt16(s) |
        CadenceType::UInt32(s) | CadenceType::UInt64(s) => {
            s.parse::<i64>().ok()
        },
        _ => None,
    }
}

// Helper to extract struct fields into a specific Rust struct (for FruitInfo example)
fn extract_fruit_info_from_cadence(cadence_value: &CadenceType) -> Option<FruitInfo> {
    match cadence_value {
        CadenceType::Struct(_, fields) | CadenceType::Resource(_, fields) => {
            let mut name = None;
            let mut color = None;
            let mut quantity = None;

            for (field_name, field_value) in fields {
                match field_name.as_str() {
                    "name" => name = extract_string_from_cadence(field_value),
                    "color" => color = extract_string_from_cadence(field_value),
                    "quantity" => quantity = extract_int_from_cadence(field_value),
                    _ => {}
                }
            }

            if let (Some(name), Some(color), Some(quantity)) = (name, color, quantity) {
                Some(FruitInfo { name, color, quantity })
            } else {
                None
            }
        },
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum TransactionStatus {
    Unknown = 0,
    Pending = 1,
    Finalized = 2,
    Executed = 3,
    Sealed = 4,
    Expired = 5,
}

impl TransactionStatus {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(TransactionStatus::Unknown),
            1 => Some(TransactionStatus::Pending),
            2 => Some(TransactionStatus::Finalized),
            3 => Some(TransactionStatus::Executed),
            4 => Some(TransactionStatus::Sealed),
            5 => Some(TransactionStatus::Expired),
            _ => None,
        }
    }
}

// Domain tag for Flow transaction signing
const TRANSACTION_DOMAIN_TAG: &str =
    "464c4f572d56302e302d7472616e73616374696f6e0000000000000000000000";

const MAX_WAIT_TIME: Duration = Duration::from_secs(60); // Maximum wait time (60 seconds)

/// Print debug information about an account's key
fn print_account_key_debug(account: &flow::entities::Account, key_index: u32) {
    if let Some(key) = account.keys.get(key_index as usize) {
        println!("=== Account Key Debug ===");
        println!("Key Index: {}", key_index);
        println!("Public Key (hex): {}", hex::encode(&key.public_key));
        println!("Hash Algorithm: {}", key.hash_algo);
        println!("Signature Algorithm: {}", key.sign_algo);
        println!("Sequence Number: {}", key.sequence_number);
        println!("Revoked: {}", key.revoked);
        println!("Weight: {}", key.weight);
        println!("========================");
    } else {
        println!("❌ No key found at index {}", key_index);
    }
}

/// Print debug information about the derived public key
fn print_public_key_debug(private_key: &SecretKey) {
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);

    println!("=== Derived Public Key Debug ===");
    println!(
        "Public Key (compressed): {}",
        hex::encode(public_key.serialize())
    );
    println!("Private key: {}", private_key.display_secret().to_string());
    println!(
        "Public Key (uncompressed): {}",
        hex::encode(public_key.serialize_uncompressed())
    );
    println!("==============================");
}

/// Enhanced transaction hash debug
fn print_transaction_hash_debug(tx: &Transaction) {
    let hash = hash_transaction(tx);

    println!("=== Transaction Hash Debug ===");
    println!("Domain Tag: {}", TRANSACTION_DOMAIN_TAG);
    println!(
        "Script (first 50 bytes): {}",
        hex::encode(&tx.script)
    );
    println!("Arguments Count: {}", tx.arguments.len());
    println!(
        "Reference Block ID: {}",
        hex::encode(&tx.reference_block_id)
    );
    println!("Gas Limit: {}", tx.gas_limit);

    if let Some(pk) = &tx.proposal_key {
        println!("Proposal Key Address: {}", hex::encode(&pk.address));
        println!("Proposal Key ID: {}", pk.key_id);
        println!("Proposal Key Sequence Number: {}", pk.sequence_number);
    }

    println!("Payer: {}", hex::encode(&tx.payer));
    println!("Authorizers: {}", tx.authorizers.len());
    for (i, auth) in tx.authorizers.iter().enumerate() {
        println!("  Authorizer {}: {}", i, hex::encode(auth));
    }

    println!("Final Hash (SHA3-256): {}", hex::encode(&hash));
    println!("============================");
}

/// Enhanced signature debug
fn print_signature_debug(
    hash: &[u8],
    signature: &secp256k1::ecdsa::Signature,
    private_key: &SecretKey,
) {
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);
    let message = Message::from_digest(<[u8; 32]>::try_from(hash).unwrap());

    println!("=== Signature Debug ===");
    println!("Message to sign (hash): {}", hex::encode(hash));
    println!(
        "Signature R value: {}",
        hex::encode(&signature.serialize_compact()[..32])
    );
    println!(
        "Signature S value: {}",
        hex::encode(&signature.serialize_compact()[32..])
    );
    println!(
        "Signature (compact, 64 bytes): {}",
        hex::encode(signature.serialize_compact())
    );
    println!(
        "Signature (DER format): {}",
        hex::encode(signature.serialize_der())
    );

    // Verify the signature
    let verification_result = secp.verify_ecdsa(&message, signature, &public_key);
    println!("Local signature verification: {}", &{
        match verification_result {
            Ok(_) => "✅ Valid".to_string(),
            Err(e) => format!("❌ Invalid: {}", e).to_string(),
        }
    });

    println!("======================");
}

/// Convert hex string to byte vector
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let clean_hex = hex_str.trim_start_matches("0x");
    Ok(hex::decode(clean_hex)?)
}

/// Parse a secp256k1 private key from hex string
fn parse_private_key(private_key_hex: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let key_bytes = hex_to_bytes(private_key_hex)?;
    let secret_key = SecretKey::from_slice(&key_bytes)?;
    Ok(secret_key)
}

/// Get account details by address
async fn get_account(
    client: &mut AccessClient<Channel>,
    address: Vec<u8>,
) -> Result<flow::entities::Account, Box<dyn std::error::Error>> {
    let request = Request::new(GetAccountRequest { address });

    let response = client.get_account(request).await?;
    let account = response.into_inner().account.ok_or("No account returned")?;

    Ok(account)
}

/// Get the latest block ID to use as reference block
async fn get_reference_block_id(
    client: &mut AccessClient<Channel>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = Request::new(GetLatestBlockRequest {
        full_block_response: false,
        is_sealed: true,
    });

    let response = client.get_latest_block(request).await?;
    let block = response.into_inner().block.ok_or("No block returned")?;

    Ok(block.id)
}

/// Calculate the hash of a transaction for signing using RLP encoding and SHA3-256
fn hash_transaction(tx: &Transaction) -> Vec<u8> {
    // Use SHA3-256 instead of SHA2-256
    let mut hasher = Sha256::new();

    // Add domain tag
    hasher.update(hex_to_bytes(TRANSACTION_DOMAIN_TAG).unwrap());

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

    // 9. Envelope Signatures (not included in the hash)
    // Removed as per diff

    // Finish RLP encoding
    let encoded = rlp.out();

    println!("RLP encoded: {}", hex::encode(encoded.clone()));

    // Hash the encoded transaction with SHA3-256
    hasher.update(&encoded);

    // Return the hash
    hasher.finalize().to_vec()
}

/// Sign a transaction with the given secp256k1 private key
fn sign_transaction(
    tx: &mut Transaction,
    signer_address: &[u8],
    key_index: u32,
    private_key: &SecretKey,
    account: &flow::entities::Account, // Add account parameter for debugging
) -> Result<(), Box<dyn std::error::Error>> {
    // Print account key information for debugging
    print_account_key_debug(account, key_index);

    // Print derived public key information
    print_public_key_debug(private_key);

    // Print transaction details for debugging
    print_transaction_hash_debug(tx);

    // Calculate the transaction hash
    let hash = hash_transaction(tx);

    // Create a Secp256k1 context
    let secp = Secp256k1::new();

    fn vec_to_array(vec: Vec<u8>) -> Result<[u8; 32], &'static str> {
        // Ensure the Vec has exactly 32 elements
        if vec.len() != 32 {
            return Err("Vec length must be 32");
        }
        // Convert to array (infallible after length check)
        Ok(vec.try_into().unwrap_or_else(|_| unreachable!()))
    }

    // Create a message from the hash
    let message = Message::from_digest(vec_to_array(hash.clone()).unwrap());

    println!("Message to sign: {}", hex::encode(&message[..]));

    // Sign the message
    let signature = secp.sign_ecdsa(&message, private_key);

    // Print signature debug information
    print_signature_debug(&hash, &signature, private_key);

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

/// Send a transaction and subscribe to status updates
pub async fn send_transaction_and_subscribe(
    client: &mut AccessClient<Channel>,
    transaction: Transaction,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Subscribe to transaction status updates
    let request = Request::new(SendAndSubscribeTransactionStatusesRequest {
        event_encoding_version: 1,
        transaction: Some(transaction),
    });

    let mut stream = client
        .send_and_subscribe_transaction_statuses(request)
        .await?
        .into_inner();

    // Set up a timeout for the subscription
    let timeout = tokio::time::sleep(MAX_WAIT_TIME);

    tokio::pin!(timeout);

    loop {
        select! {
            // Wait for the next status update or timeout
            result = stream.next() => {
                match result {
                    Some(Ok(status_response)) => {
                        if let Some(response) = status_response.transaction_results {
                            let status = TransactionStatus::from_i32(response.status)
                                .unwrap_or(TransactionStatus::Unknown);

                            println!("Transaction status update: {:?}", status);

                            match status {
                                TransactionStatus::Sealed => {
                                    println!("Transaction sealed successfully!");
                                    return Ok(response.transaction_id);
                                }
                                TransactionStatus::Expired => {
                                    return Err("Transaction expired".into());
                                }
                                // Continue waiting for other statuses
                                _ => continue,
                            }
                        } else {
                            println!("Received status update with no transaction results");
                            continue;
                        }
                    }
                    Some(Err(e)) => {
                        return Err(format!("Error from transaction status stream: {}", e).into());
                    }
                    None => {
                        return Err("Transaction status stream closed unexpectedly".into());
                    }
                }
            }
            // Handle timeout
            _ = &mut timeout => {
                return Err("Maximum wait time exceeded".into());
            }
        }
    }
}

/// Execute a script at the latest block and return the result
async fn execute_script(
    client: &mut AccessClient<Channel>,
    script: Vec<u8>,
    arguments: Vec<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = Request::new(ExecuteScriptAtLatestBlockRequest {
        script,
        arguments,
    });

    let response = client.execute_script_at_latest_block(request).await?;
    let result = response.into_inner().value;

    Ok(result)
}

/// Get events for a specific height range
async fn get_events_for_height_range(
    client: &mut AccessClient<Channel>,
    event_type: String,
    start_height: u64,
    end_height: u64,
) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let request = Request::new(GetEventsForHeightRangeRequest {
        r#type: event_type,
        start_height,
        end_height,
        event_encoding_version: 0,
    });

    let response = client.get_events_for_height_range(request).await?;
    let results = response.into_inner().results;

    let mut events = Vec::new();
    for block_events in results {
        events.extend(block_events.events);
    }

    Ok(events)
}

// Custom struct for the Fruit example
#[derive(Debug, Deserialize)]
struct FruitInfo {
    name: String,
    color: String,
    quantity: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the Flow Testnet Access API
    let channel = Channel::from_static("http://access.testnet.nodes.onflow.org:9000")
        .connect()
        .await?;

    let mut client = AccessClient::new(channel);

    // Set your Flow account address and private key
    let account_address_hex = "788db9ec197a75de"; // Without 0x prefix
    let private_key_hex = "3b75e9e624b7aec74181c37270296fe4718af0f674012758df99e59ab0f85b50"; // Your private key

    // Convert address from hex
    let account_address = hex_to_bytes(account_address_hex)?;

    // Parse the private key (as secp256k1 key)
    let private_key = parse_private_key(private_key_hex)?;

    // Get account information to retrieve the latest sequence number
    let account = get_account(&mut client, account_address.clone()).await?;

    // Use the first key (index 0)
    let key_index = 0u32;

    // Get the current sequence number for the key
    let sequence_number = account
        .keys
        .get(key_index as usize)
        .ok_or("No key found at the specified index")?
        .sequence_number;

    println!(
        "Account retrieved. Current sequence number: {}",
        sequence_number
    );

    // Get latest block ID for reference
    let reference_block_id = get_reference_block_id(&mut client).await?;
    println!("Reference block ID: {}", hex::encode(&reference_block_id));

    // PART 1: Transaction with parameters
    println!("\n=== EXECUTING TRANSACTION WITH PARAMETERS ===\n");

    // Create a transaction with parameters
    // Modified script to accept a string parameter and a UFix64 parameter
    let script_with_params = r#"
        transaction(message: String, amount: UFix64) {
            prepare(signer: AuthAccount) {
                log("Transaction executed")
            }
            execute {
                log("Message from parameter: ".concat(message))
                log("Amount: ".concat(amount.toString()))
            }
        }
    "#.as_bytes().to_vec();

    // Create the transaction with the new script
    let mut transaction = Transaction {
        script: script_with_params,
        arguments: vec![],  // We'll populate this with parameters
        reference_block_id,
        gas_limit: 100,
        proposal_key: Some(transaction::ProposalKey {
            address: account_address.clone(),
            key_id: key_index,
            sequence_number: sequence_number.into(),
        }),
        payer: account_address.clone(),
        authorizers: vec![account_address.clone()],
        payload_signatures: vec![],
        envelope_signatures: vec![],
    };

    // Add string parameter using JSON encoding
    let message = "Hello, Flow!";
    let encoded_message = serde_json::to_string(&message)?.into_bytes();
    transaction.arguments.push(encoded_message);

    // Add UFix64 parameter (a fixed-point decimal in Flow)
    // For UFix64, we encode as a string in the format "123.456"
    let amount = "100.0";
    let encoded_amount = serde_json::to_string(&amount)?.into_bytes();
    transaction.arguments.push(encoded_amount);

    // Print parameters for debugging
    println!("Parameters added to transaction:");
    println!("  Message: {}", message);
    println!("  Amount: {}", amount);

    // Sign the transaction
    sign_transaction(
        &mut transaction,
        &account_address,
        key_index,
        &private_key,
        &account,
    )?;

    println!("Transaction signed. Sending to network...");

    // Send transaction and subscribe to status updates
    let tx_id = send_transaction_and_subscribe(&mut client, transaction).await?;
    println!("Transaction with ID {} is sealed", hex::encode(&tx_id));

    // PART 2: Execute a script that returns a value
    println!("\n=== EXECUTING SCRIPT WITH RETURN VALUE ===\n");

    // Define a script that returns an array of strings
    let script_with_return = r#"
        access(all) fun main(prefix: String): [String] {
            let items: [String] = ["apple", "banana", "cherry", "date"]
            let result: [String] = []
            
            for item in items {
                result.append(prefix.concat(": ").concat(item))
            }
            
            return result
        }
    "#.as_bytes().to_vec();

    // Prepare script arguments
    let prefix = "Fruit";
    // Flow expects objects for script parameters, not just a string
    let prefix_obj = serde_json::json!({ "type": "String", "value": prefix });
    let encoded_prefix = serde_json::to_vec(&prefix_obj)?;
    let script_args = vec![encoded_prefix];

    // Execute the script
    println!("Executing script that returns an array of strings...");
    let result_bytes = execute_script(&mut client, script_with_return, script_args).await?;

    // Parse the result (it's a JSON-encoded array of strings)
    let result_string = String::from_utf8(result_bytes)?;
    println!("Script result (raw JSON): {}", result_string);

    // Parse the result with our new Cadence-JSON deserializer
    let cadence_result: CadenceType = serde_json::from_str(&result_string)?;
    println!("Parsed Cadence result: {:?}", cadence_result);

    // Extract the string values using our helper function
    let string_values = match &cadence_result {
        CadenceType::Array(items) => {
            items.iter()
                .filter_map(|item| {
                    if let CadenceType::String(s) = item {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
        },
        _ => vec![],
    };

    println!("Extracted String values:");
    for (i, item) in string_values.iter().enumerate() {
        println!("  {}. {}", i + 1, item);
    }

    // PART 3: Execute a script that returns a dictionary
    println!("\n=== EXECUTING SCRIPT WITH DICTIONARY RETURN VALUE ===\n");

    // Define a script that returns a dictionary (mapping of string -> integer)
    let script_with_dict_return = r#"
        access(all) fun main(): {String: Int} {
            let counts: {String: Int} = {
                "apple": 5,
                "banana": 10,
                "cherry": 15
            }
            return counts
        }
    "#.as_bytes().to_vec();

    // Execute the script
    println!("Executing script that returns a dictionary...");
    let dict_result_bytes = execute_script(&mut client, script_with_dict_return, vec![]).await?;

    // Parse the result (it's a JSON-encoded dictionary)
    let dict_result_string = String::from_utf8(dict_result_bytes)?;
    println!("Script result (raw JSON): {}", dict_result_string);

    // Parse the result with our Cadence-JSON deserializer
    let cadence_dict_result: CadenceType = serde_json::from_str(&dict_result_string)?;
    println!("Parsed Cadence dictionary: {:?}", cadence_dict_result);

    // Extract the key-value pairs
    let fruit_counts = extract_string_int_map_from_cadence(&cadence_dict_result);
    println!("Extracted dictionary values:");
    for (fruit, count) in &fruit_counts {
        println!("  {}: {}", fruit, count);
    }

    // PART 4: Execute a script that returns a composite type
    println!("\n=== EXECUTING SCRIPT WITH COMPOSITE TYPE RETURN VALUE ===\n");

    // Define a script that returns a composite type (struct)
    let script_with_struct_return = r#"
        access(all) struct FruitInfo {
            access(all) let name: String
            access(all) let color: String
            access(all) let quantity: Int
            
            init(name: String, color: String, quantity: Int) {
                self.name = name
                self.color = color
                self.quantity = quantity
            }
        }
        
        access(all) fun main(): FruitInfo {
            return FruitInfo(name: "Mango", color: "Yellow", quantity: 42)
        }
    "#.as_bytes().to_vec();

    // Execute the script
    println!("Executing script that returns a composite type...");
    let struct_result_bytes = execute_script(&mut client, script_with_struct_return, vec![]).await?;

    // Parse the result (it's a JSON-encoded struct)
    let struct_result_string = String::from_utf8(struct_result_bytes)?;
    println!("Script result (raw JSON): {}", struct_result_string);

    // Parse the result with our Cadence-JSON deserializer
    let cadence_struct_result: CadenceType = serde_json::from_str(&struct_result_string)?;
    println!("Parsed Cadence struct: {:?}", cadence_struct_result);

    // Extract the struct fields into our FruitInfo struct
    if let Some(fruit_info) = extract_fruit_info_from_cadence(&cadence_struct_result) {
        println!("Extracted FruitInfo struct:");
        println!("  Name: {}", fruit_info.name);
        println!("  Color: {}", fruit_info.color);
        println!("  Quantity: {}", fruit_info.quantity);
    } else {
        println!("Failed to extract FruitInfo struct from result");
    }

    println!("\nAll operations completed successfully!");

    Ok(())
}