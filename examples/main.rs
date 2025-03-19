use std::time::Duration;
use flow_access_api::client::*;
use flow_access_api::keys::{hex_to_bytes, parse_private_key};
use flow_access_api::network::Network;
use serde::{Deserialize};
use serde_cadence::{self, CadenceValue, FromCadenceValue, ToCadenceValue};
use flow_access_api::flow::entities::TransactionStatus;
use flow_access_api::transactions::sign_transaction;

// Custom struct for the Fruit example
#[derive(Debug, Deserialize, ToCadenceValue, FromCadenceValue)]
struct FruitInfo {
    name: String,
    color: String,
    quantity: i64,
}

#[tokio::main]
async fn main() -> flow_access_api::Result<()> {
    // Connect to the Flow Testnet Access API
    let mut client = FlowRcpClient::try_new(Network::Custom {
        endpoint: "http://access.testnet.nodes.onflow.org:9000".to_string()
    }).await?;

    // Set your Flow account address and private key
    let account_address_hex = "788db9ec197a75de"; // Without 0x prefix
    let private_key_hex = "3b75e9e624b7aec74181c37270296fe4718af0f674012758df99e59ab0f85b50"; // Your private key

    // Convert address from hex
    let account_address = hex_to_bytes(account_address_hex)?;

    // Parse the private key (as secp256k1 key)
    let private_key = parse_private_key(private_key_hex)?;

    // PART 1: Transaction with parameters
    println!("\n=== EXECUTING TRANSACTION WITH PARAMETERS ===\n");

    // Modified script to accept a string parameter and a UFix64 parameter
    let script_with_params = r#"
        transaction(message: String, amount: UFix64) {
            prepare(signer: &Account) {
                log("Transaction executed")
            }
            execute {
                log("Message from parameter: ".concat(message))
                log("Amount: ".concat(amount.toString()))
            }
        }
    "#;

    // Create parameters
    let message = "Hello, Flow!";
    let amount = 100_f64;
    
    // Create and sign the transaction using the library
    let (mut tx, tx_hash) = client.create_transaction_with_params(
        script_with_params,
        &[&message, &CadenceValue::UFix64 { value: format!("{:.2}", amount) }],
        account_address_hex,
        100 // gas limit
    ).await?;

    // For visualization purposes only - not needed for real usage
    println!("Transaction created with hash: {}", hex::encode(&tx_hash));

    // Sign the transaction using library functionality
    sign_transaction(
        &mut tx,
        account_address_hex,
        0,
        &private_key,
    )?;

    println!("Transaction signed. Sending to network...");

    // Send transaction and subscribe to status updates
    let tx_id = client.send_transaction_and_subscribe(
        tx,
        TransactionStatus::Sealed,
        Duration::from_secs(60)
    ).await?;
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
    "#;

    // Prepare script arguments
    let prefix = "Fruit";

    // Execute the script using the library's method
    println!("Executing script that returns an array of strings...");
    let cadence_result = client
        .execute_script(script_with_return, &[&prefix])
        .await?;

    println!("Parsed Cadence result: {:?}", cadence_result);

    // Extract the string values using the FromCadenceValue trait
    let string_values: Vec<String> = serde_cadence::from_cadence_value(&cadence_result)?;

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
    "#;

    // Execute the script using the library's method
    println!("Executing script that returns a dictionary...");
    let cadence_dict_result = client
        .execute_script(script_with_dict_return, &[])
        .await?;

    println!("Parsed Cadence dictionary: {:?}", cadence_dict_result);

    // Extract the key-value pairs using the FromCadenceValue trait
    let fruit_counts: std::collections::HashMap<String, i64> =
        serde_cadence::from_cadence_value(&cadence_dict_result)?;

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
    "#;

    // Execute the script using the library's method
    println!("Executing script that returns a composite type...");
    let cadence_struct_result = client
        .execute_script(script_with_struct_return, &[])
        .await?;

    println!("Parsed Cadence struct: {:?}", cadence_struct_result);

    // Extract the struct fields directly using FromCadenceValue trait
    let fruit_info: FruitInfo = serde_cadence::from_cadence_value(&cadence_struct_result)?;

    println!("Extracted FruitInfo struct:");
    println!("  Name: {}", fruit_info.name);
    println!("  Color: {}", fruit_info.color);
    println!("  Quantity: {}", fruit_info.quantity);

    println!("\nAll operations completed successfully!");

    Ok(())
}
