#[derive(Clone)]
pub enum Network {
    Mainnet,
    Testnet,
    Custom { endpoint: String },
}

impl From<Network> for String {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "access.mainnet.nodes.onflow.org:9000".into(),
            Network::Testnet => "access.devnet.nodes.onflow.org:9000".into(),
            Network::Custom { endpoint } => endpoint
        }
    }
}
