use std::net::SocketAddr;

use quinn::Endpoint;
use tokio::task::JoinSet;

use super::{
    QuicInterfaceError, QuicLinkConfig,
    common::{QuicInterfaceState, run_incoming_connection, server_config},
};
use crate::{RuntimeHandle, interface::Interface};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QuicServerConfig {
    pub bind_address: SocketAddr,
    #[serde(default = "default_maximum_connections")]
    pub maximum_connections: usize,
    #[serde(default)]
    pub link: QuicLinkConfig,
}

impl QuicServerConfig {
    pub fn new(bind_address: SocketAddr) -> Self {
        Self {
            bind_address,
            maximum_connections: default_maximum_connections(),
            link: QuicLinkConfig::default(),
        }
    }
}

pub struct QuicServerInterface(QuicInterfaceState);

impl QuicServerInterface {
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.0.local_addr()
    }
}

impl Interface for QuicServerInterface {
    type Config = QuicServerConfig;
    type Error = QuicInterfaceError;

    async fn new(runtime: RuntimeHandle, config: Self::Config) -> Result<Self, Self::Error> {
        config.link.validate()?;
        if config.maximum_connections == 0 {
            return Err(QuicInterfaceError::InvalidConfig(
                "maximum_connections must be nonzero",
            ));
        }
        let endpoint = Endpoint::server(server_config()?, config.bind_address)
            .map_err(QuicInterfaceError::Bind)?;
        let task_endpoint = endpoint.clone();
        let task = tokio::spawn(run_server(task_endpoint, runtime, config));
        Ok(Self(QuicInterfaceState::new(endpoint, task)))
    }
}

async fn run_server(endpoint: Endpoint, runtime: RuntimeHandle, config: QuicServerConfig) {
    let mut connections = JoinSet::<Result<(), QuicInterfaceError>>::new();
    let mut failure_reported = false;
    loop {
        tokio::select! {
            () = runtime.stopped() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                if connections.len() >= config.maximum_connections {
                    incoming.refuse();
                    continue;
                }
                let runtime = runtime.clone();
                let link = config.link.clone();
                connections.spawn(run_incoming_connection(incoming, runtime, link));
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                match result {
                    Ok(Ok(())) => failure_reported = false,
                    Ok(Err(error)) if !failure_reported => {
                        runtime.interface_error(None, error.to_string());
                        failure_reported = true;
                    }
                    Err(error) if !error.is_cancelled() && !failure_reported => {
                        runtime.interface_error(None, format!("QUIC connection task failed: {error}"));
                        failure_reported = true;
                    }
                    Ok(Err(_)) | Err(_) => {}
                }
            }
        }
    }
    endpoint.close(0_u8.into(), b"interface stopped");
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
            && !failure_reported
        {
            runtime.interface_error(None, format!("QUIC connection task failed: {error}"));
            failure_reported = true;
        }
    }
}

const fn default_maximum_connections() -> usize {
    256
}
