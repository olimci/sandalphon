use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use quinn::Endpoint;

use super::{
    QuicInterfaceError, QuicLinkConfig, QuicReconnectConfig,
    common::{
        QuicInterfaceState, client_config, increase_reconnect_delay, reconnect_delay,
        run_outgoing_connection,
    },
};
use crate::{RuntimeHandle, interface::Interface};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QuicClientConfig {
    pub server_address: SocketAddr,
    pub bind_address: Option<SocketAddr>,
    #[serde(default)]
    pub reconnect: QuicReconnectConfig,
    #[serde(default)]
    pub link: QuicLinkConfig,
}

impl QuicClientConfig {
    pub fn new(server_address: SocketAddr) -> Self {
        Self {
            server_address,
            bind_address: None,
            reconnect: QuicReconnectConfig::default(),
            link: QuicLinkConfig::default(),
        }
    }
}

pub struct QuicClientInterface(QuicInterfaceState);

impl QuicClientInterface {
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.0.local_addr()
    }
}

impl Interface for QuicClientInterface {
    type Config = QuicClientConfig;
    type Error = QuicInterfaceError;

    async fn new(runtime: RuntimeHandle, config: Self::Config) -> Result<Self, Self::Error> {
        config.link.validate()?;
        config.reconnect.validate()?;
        let bind_address = config
            .bind_address
            .unwrap_or_else(|| unspecified_address_for(config.server_address));
        let mut endpoint = Endpoint::client(bind_address).map_err(QuicInterfaceError::Bind)?;
        endpoint.set_default_client_config(client_config()?);
        let task_endpoint = endpoint.clone();
        let task = tokio::spawn(run_client(task_endpoint, runtime, config));

        Ok(Self(QuicInterfaceState::new(endpoint, task)))
    }
}

async fn run_client(endpoint: Endpoint, runtime: RuntimeHandle, config: QuicClientConfig) {
    let mut delay = config.reconnect.initial_delay;
    let mut failure_reported = false;
    loop {
        let attempt = connect(&endpoint, &runtime, &config);
        tokio::pin!(attempt);
        let result = tokio::select! {
            () = runtime.stopped() => break,
            result = &mut attempt => result,
        };
        let established = match result {
            Ok(()) => {
                failure_reported = false;
                true
            }
            Err(error) => {
                if !failure_reported {
                    runtime.interface_error(None, format!("{}: {error}", config.server_address));
                    failure_reported = true;
                }
                false
            }
        };
        if runtime.is_stopped() {
            break;
        }
        if established {
            delay = config.reconnect.initial_delay;
        }
        tokio::select! {
            () = runtime.stopped() => break,
            () = tokio::time::sleep(reconnect_delay(delay)) => {}
        }
        if !established {
            delay = increase_reconnect_delay(delay, config.reconnect.maximum_delay);
        }
    }
}

async fn connect(
    endpoint: &Endpoint,
    runtime: &RuntimeHandle,
    config: &QuicClientConfig,
) -> Result<(), QuicInterfaceError> {
    run_outgoing_connection(
        endpoint,
        config.server_address,
        runtime.clone(),
        config.link.clone(),
    )
    .await
}

fn unspecified_address_for(server: SocketAddr) -> SocketAddr {
    SocketAddr::new(
        match server.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    )
}
