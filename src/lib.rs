use anyhow::anyhow;
use derive_more::From;

pub mod client;

pub mod network;

pub mod keys;

pub mod transactions;

pub mod flow {
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

#[derive(Debug, From)]
pub enum Error {
    #[from]
    KeysError(keys::Error),
    #[from]
    TransactionsError(transactions::Error),
    #[from]
    ClientError(client::Error),
}

pub type Result<T> = std::result::Result<T, client::Error>;

impl From<Error> for anyhow::Error {
    fn from(value: Error) -> Self {
        anyhow!(format!("{:?}", value))
    }
}
