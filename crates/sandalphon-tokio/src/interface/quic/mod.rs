use std::time::Duration;

use sandalphon_core::network::TransitGroupId;
use thiserror::Error;

use crate::runtime::{LinkConfig, RuntimeHandleError};

mod client;
mod common;
mod lan;
mod server;

pub use client::{QuicClientConfig, QuicClientInterface};
pub use lan::{QuicLanConfig, QuicLanInterface};
pub use server::{QuicServerConfig, QuicServerInterface};

const DEFAULT_MTU: u16 = 16 * 1024;
const DEFAULT_MINIMUM_MTU: u16 = 1_200;
const DEFAULT_INCOMPLETE_LIMIT: usize = 64;
const DEFAULT_OUTGOING_CAPACITY: usize = 64;
const DEFAULT_EDGE_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_RECONNECT_MAXIMUM_DELAY: Duration = Duration::from_secs(30);
const MINIMUM_MTU: u16 = 26;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct QuicReconnectConfig {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
}

impl Default for QuicReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: DEFAULT_RECONNECT_INITIAL_DELAY,
            maximum_delay: DEFAULT_RECONNECT_MAXIMUM_DELAY,
        }
    }
}

impl QuicReconnectConfig {
    fn validate(&self) -> Result<(), QuicInterfaceError> {
        if self.initial_delay.is_zero() {
            return Err(QuicInterfaceError::InvalidConfig(
                "reconnect initial_delay must be nonzero",
            ));
        }
        if self.maximum_delay < self.initial_delay {
            return Err(QuicInterfaceError::InvalidConfig(
                "reconnect maximum_delay must not be shorter than initial_delay",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct QuicLinkConfig {
    pub mtu: u16,
    pub minimum_mtu: u16,
    pub edge_lifetime: Duration,
    pub setup_timeout: Duration,
    pub incomplete_limit: usize,
    pub outgoing_capacity: usize,
    pub transit_groups: Vec<TransitGroupId>,
}

impl Default for QuicLinkConfig {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            minimum_mtu: DEFAULT_MINIMUM_MTU,
            edge_lifetime: DEFAULT_EDGE_LIFETIME,
            setup_timeout: DEFAULT_SETUP_TIMEOUT,
            incomplete_limit: DEFAULT_INCOMPLETE_LIMIT,
            outgoing_capacity: DEFAULT_OUTGOING_CAPACITY,
            transit_groups: Vec::new(),
        }
    }
}

impl QuicLinkConfig {
    pub(super) fn validate(&self) -> Result<(), QuicInterfaceError> {
        if self.mtu <= self.minimum_mtu {
            return Err(QuicInterfaceError::InvalidConfig(
                "mtu must be greater than minimum_mtu",
            ));
        }
        if self.mtu < MINIMUM_MTU {
            return Err(QuicInterfaceError::InvalidConfig(
                "mtu is smaller than Sandalphon's link framing overhead",
            ));
        }
        if self.incomplete_limit == 0 {
            return Err(QuicInterfaceError::InvalidConfig(
                "incomplete_limit must be nonzero",
            ));
        }
        if self.edge_lifetime.is_zero() {
            return Err(QuicInterfaceError::InvalidConfig(
                "edge_lifetime must be nonzero",
            ));
        }
        if self.setup_timeout.is_zero() {
            return Err(QuicInterfaceError::InvalidConfig(
                "setup_timeout must be nonzero",
            ));
        }
        if self.outgoing_capacity == 0 {
            return Err(QuicInterfaceError::InvalidConfig(
                "outgoing_capacity must be nonzero",
            ));
        }
        Ok(())
    }

    pub(super) fn runtime_config(&self) -> LinkConfig {
        LinkConfig {
            mtu: self.mtu,
            minimum_mtu: self.minimum_mtu,
            edge_lifetime_ms: u64::try_from(self.edge_lifetime.as_millis()).unwrap_or(u64::MAX),
            incomplete_limit: self.incomplete_limit,
            transit_groups: self.transit_groups.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum QuicInterfaceError {
    #[error("invalid QUIC interface configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("could not create a self-signed QUIC certificate")]
    Certificate(#[from] rcgen::Error),
    #[error("could not configure QUIC TLS")]
    Tls(#[from] rustls::Error),
    #[error("could not bind the QUIC endpoint")]
    Bind(#[source] std::io::Error),
    #[error("could not configure IPv6 multicast discovery")]
    Discovery(#[source] std::io::Error),
    #[error("could not start the QUIC connection")]
    Connect(#[from] quinn::ConnectError),
    #[error("the QUIC handshake failed")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC connection setup timed out")]
    SetupTimeout,
    #[error("the Sandalphon link failed: {0}")]
    Link(String),
    #[error(transparent)]
    Runtime(#[from] RuntimeHandleError),
}
