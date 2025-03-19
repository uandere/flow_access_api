#![allow(unused)]
use crate::client::Error::*;
use crate::flow::access::access_api_client::AccessApiClient;
use crate::flow::access::{
    ExecuteScriptAtLatestBlockRequest, GetAccountAtLatestBlockRequest,
    GetEventsForHeightRangeRequest, GetLatestBlockRequest,
    SendAndSubscribeTransactionStatusesRequest,
};
use crate::flow::entities::{transaction, Account, Event, Transaction, TransactionStatus};
use crate::keys::hex_to_bytes;
use crate::network::Network;
use crate::transactions;
use crate::transactions::hash_transaction;
use derive_more::From;
use futures::StreamExt;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde_cadence::{to_cadence_value, CadenceValue, ToCadenceValue};
use sha3::{Digest, Sha3_256};
use std::str::FromStr;
use std::time::Duration;
use tokio::select;
use tonic::transport::{Channel, Uri};
use tonic::Request;

#[derive(Debug, From)]
pub enum Error {
    #[from]
    TonicError(tonic::transport::Error),
    #[from]
    InvalidEndpoint(tonic::codegen::http::uri::InvalidUri),
    CantGetAccount {
        address: String,
    },
    #[from]
    TonicStatusError(tonic::Status),
    TransactionExpired,
    TransactionTimeoutExceeded,
    TransactionStreamClosedUnexpectedly,
    DigestLenError(Vec<u8>),
    #[from]
    TransactionsError(transactions::Error),
    NoBlockReturned,
    #[from]
    KeysError(crate::keys::Error),
    #[from]
    CadenceJsonError(serde_cadence::Error),
    #[from]
    SerdeError(serde_json::Error),
    NoKeyAtIndex {
        idx: u32,
    },
    #[from]
    ResultUTF8Error(std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct FlowRcpClient {
    access_client: AccessApiClient<Channel>,
}


impl FlowRcpClient {
    pub async fn try_new(network: Network) -> Result<FlowRcpClient> {
        let endpoint: String = network.into();

        let channel = Channel::builder(Uri::from_str(&endpoint)?)
            .connect()
            .await?;

        let client = FlowRcpClient {
            access_client: AccessApiClient::new(channel),
        };

        Ok(client)
    }

    pub async fn create_transaction_with_params(
        &mut self,
        script: &str,
        params: &[&dyn ToCadenceValue],
        sender_address_hex: &str,
        gas_limit: u64,
    ) -> Result<(Transaction, Vec<u8>)> {
        let reference_block_id = self.get_reference_block_id().await?;
        let account_address = hex_to_bytes(sender_address_hex)?;
        let account = self.get_account(account_address.clone()).await?;

        let key_index = 0u32;

        let sequence_number = account
            .keys
            .get(key_index as usize)
            .ok_or(NoKeyAtIndex { idx: key_index })?
            .sequence_number;

        let mut tx = Transaction {
            script: script.as_bytes().to_vec(),
            arguments: vec![], // We'll populate this with parameters
            reference_block_id,
            gas_limit: gas_limit,
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

        for &param in params {
            let cadence_message = to_cadence_value(param)?;
            // Flow API requires JSON serialization for transaction arguments
            let encoded_message = serde_json::to_string(&cadence_message)?.into_bytes();
            tx.arguments.push(encoded_message);
        }

        // Use SHA3-256 instead of SHA2-256
        let mut hasher = Sha3_256::new();

        // Add domain tag
        hasher.update(hex_to_bytes(transactions::TRANSACTION_DOMAIN_TAG)?);

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

        // Hash the encoded transaction with SHA3-256
        hasher.update(&encoded);

        // Return the hash
        Ok((tx, hasher.finalize().to_vec()))
    }
    
    /// Send a transaction and subscribe to status updates.
    pub async fn send_transaction_and_subscribe(
        &mut self,
        transaction: Transaction,
        target_status: TransactionStatus,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        // Subscribe to transaction status updates
        let request = Request::new(SendAndSubscribeTransactionStatusesRequest {
            event_encoding_version: 1,
            transaction: Some(transaction),
        });

        let mut stream = self
            .access_client
            .send_and_subscribe_transaction_statuses(request)
            .await?
            .into_inner();

        // Set up a timeout for the subscription
        let timeout = tokio::time::sleep(timeout);

        tokio::pin!(timeout);

        loop {
            select! {
                // Wait for the next status update or timeout
                result = stream.next() => {
                    match result {
                        Some(Ok(status_response)) => {
                            if let Some(response) = status_response.transaction_results {
                                let status = TransactionStatus::try_from(response.status)
                                    .unwrap_or(TransactionStatus::Unknown);

                                println!("Transaction status update: {:?}", status);

                                if status == target_status {
                                    return Ok(response.transaction_id);
                                }

                                match status {
                                    TransactionStatus::Expired => {
                                        return Err(TransactionExpired);
                                    }
                                    _ => continue,
                                }
                            } else {
                                continue;
                            }
                        }
                        Some(Err(e)) => {
                            return Err(e.into());
                        }
                        None => {
                            return Err(TransactionStreamClosedUnexpectedly);
                        }
                    }
                }
                // Handle timeout
                _ = &mut timeout => {
                    return Err(TransactionTimeoutExceeded);
                }
            }
        }
    }

    /// Execute a script at the latest block and return the result
    pub async fn execute_script(
        &mut self,
        script: &str,
        arguments: &[&dyn ToCadenceValue],
    ) -> Result<CadenceValue> {
        let script = script.as_bytes().to_vec();
        let mut cadence_arguments = vec![];

        for arg in arguments {
            cadence_arguments.push(serde_json::to_vec(&arg.to_cadence_value()?)?)
        }

        let request = Request::new(ExecuteScriptAtLatestBlockRequest {
            script,
            arguments: cadence_arguments,
        });

        let response = self
            .access_client
            .execute_script_at_latest_block(request)
            .await?;

        let result = response.into_inner().value;

        let result_string = String::from_utf8(result)?;

        let result: CadenceValue = serde_cadence::from_str(&result_string)?;

        Ok(result)
    }

    /// Get events for a specific height range.
    async fn get_events_for_height_range(
        &mut self,
        event_type: String,
        start_height: u64,
        end_height: u64,
    ) -> std::result::Result<Vec<Event>, Box<dyn std::error::Error>> {
        let request = Request::new(GetEventsForHeightRangeRequest {
            r#type: event_type,
            start_height,
            end_height,
            event_encoding_version: 0,
        });

        let response = self
            .access_client
            .get_events_for_height_range(request)
            .await?;
        let results = response.into_inner().results;

        let mut events = Vec::new();
        for block_events in results {
            events.extend(block_events.events);
        }

        Ok(events)
    }

    /// Get account details by address.
    pub async fn get_account(&mut self, address: Vec<u8>) -> Result<Account> {
        let request = Request::new(GetAccountAtLatestBlockRequest {
            address: address.clone(),
        });

        let response = self
            .access_client
            .get_account_at_latest_block(request)
            .await?;
        let account = response.into_inner().account.ok_or(CantGetAccount {
            address: hex::encode(&address),
        })?;

        Ok(account)
    }

    pub async fn get_reference_block_id(&mut self) -> Result<Vec<u8>> {
        let request = Request::new(GetLatestBlockRequest {
            full_block_response: false,
            is_sealed: true,
        });

        let response = self.access_client.get_latest_block(request).await?;
        let block = response.into_inner().block.ok_or(NoBlockReturned {})?;

        Ok(block.id)
    }
}
