use std::{
    collections::BTreeMap,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use quinn::Endpoint;
use sandalphon_core::crypto::PublicKey;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{Instant, MissedTickBehavior},
};

use super::{
    QuicInterfaceError, QuicLinkConfig, QuicReconnectConfig,
    common::{
        QuicInterfaceState, client_config, increase_reconnect_delay, reconnect_delay,
        run_incoming_connection, run_outgoing_connection, server_config,
    },
};
use crate::{RuntimeHandle, interface::Interface};

const ADVERTISEMENT_MAGIC: &[u8; 8] = b"SANDLAN\0";
const ADVERTISEMENT_VERSION: u8 = 1;
const ADVERTISEMENT_LEN: usize = ADVERTISEMENT_MAGIC.len() + 1 + size_of::<u16>() + PublicKey::LEN;
const DEFAULT_ADVERTISEMENT_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_MAXIMUM_PEERS: usize = 256;
const DEFAULT_DISCOVERY_PORT: u16 = 44_822;
const DEFAULT_DISCOVERY_GROUP: Ipv6Addr =
    Ipv6Addr::new(0xff12, 0, 0, 0, 0x7361, 0x6e64, 0x616c, 0x7068);

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QuicLanConfig {
    pub interface_index: u32,
    #[serde(default = "default_discovery_address")]
    pub discovery_address: SocketAddrV6,
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddrV6,
    #[serde(default = "default_advertisement_interval")]
    pub advertisement_interval: Duration,
    #[serde(default = "default_peer_timeout")]
    pub peer_timeout: Duration,
    #[serde(default = "default_maximum_peers")]
    pub maximum_peers: usize,
    #[serde(default)]
    pub reconnect: QuicReconnectConfig,
    #[serde(default)]
    pub link: QuicLinkConfig,
}

impl QuicLanConfig {
    pub fn new(interface_index: u32) -> Self {
        Self {
            interface_index,
            discovery_address: default_discovery_address(),
            bind_address: default_bind_address(),
            advertisement_interval: default_advertisement_interval(),
            peer_timeout: default_peer_timeout(),
            maximum_peers: default_maximum_peers(),
            reconnect: QuicReconnectConfig::default(),
            link: QuicLinkConfig::default(),
        }
    }

    fn validate(&self) -> Result<(), QuicInterfaceError> {
        self.link.validate()?;
        self.reconnect.validate()?;
        if self.interface_index == 0 {
            return Err(QuicInterfaceError::InvalidConfig(
                "LAN interface_index must be nonzero",
            ));
        }
        if !self.discovery_address.ip().is_multicast() {
            return Err(QuicInterfaceError::InvalidConfig(
                "LAN discovery_address must be multicast",
            ));
        }
        if self.discovery_address.port() == 0 {
            return Err(QuicInterfaceError::InvalidConfig(
                "LAN discovery port must be nonzero",
            ));
        }
        if self.advertisement_interval.is_zero() {
            return Err(QuicInterfaceError::InvalidConfig(
                "LAN advertisement_interval must be nonzero",
            ));
        }
        if self.peer_timeout <= self.advertisement_interval {
            return Err(QuicInterfaceError::InvalidConfig(
                "LAN peer_timeout must be longer than advertisement_interval",
            ));
        }
        if self.maximum_peers == 0 {
            return Err(QuicInterfaceError::InvalidConfig(
                "LAN maximum_peers must be nonzero",
            ));
        }
        Ok(())
    }
}

pub struct QuicLanInterface(QuicInterfaceState);

impl QuicLanInterface {
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.0.local_addr()
    }
}

impl Interface for QuicLanInterface {
    type Config = QuicLanConfig;
    type Error = QuicInterfaceError;

    async fn new(runtime: RuntimeHandle, config: Self::Config) -> Result<Self, Self::Error> {
        config.validate()?;
        let discovery = discovery_socket(&config)?;
        let mut endpoint = Endpoint::server(server_config()?, SocketAddr::V6(config.bind_address))
            .map_err(QuicInterfaceError::Bind)?;
        endpoint.set_default_client_config(client_config()?);
        let quic_port = endpoint
            .local_addr()
            .map_err(QuicInterfaceError::Bind)?
            .port();
        let task_endpoint = endpoint.clone();
        let task = tokio::spawn(run_lan(
            task_endpoint,
            discovery,
            runtime,
            config,
            quic_port,
        ));
        Ok(Self(QuicInterfaceState::new(endpoint, task)))
    }
}

struct Peer {
    address: SocketAddr,
    last_seen: Instant,
    next_attempt: Instant,
    reconnect_delay: Duration,
    active: bool,
    failure_reported: bool,
}

struct ConnectionOutcome {
    peer: Option<PublicKey>,
    established: bool,
    error: Option<String>,
}

async fn run_lan(
    endpoint: Endpoint,
    discovery: UdpSocket,
    runtime: RuntimeHandle,
    config: QuicLanConfig,
    quic_port: u16,
) {
    let local = runtime.public_key();
    let advertisement = encode_advertisement(local, quic_port);
    let discovery_target = SocketAddr::V6(SocketAddrV6::new(
        *config.discovery_address.ip(),
        config.discovery_address.port(),
        config.discovery_address.flowinfo(),
        config.interface_index,
    ));
    let maintenance_interval = config
        .reconnect
        .initial_delay
        .min(Duration::from_millis(250));
    let mut advertisements = tokio::time::interval(config.advertisement_interval);
    advertisements.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut maintenance = tokio::time::interval(maintenance_interval);
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut peers = BTreeMap::<PublicKey, Peer>::new();
    let mut connections = JoinSet::<ConnectionOutcome>::new();
    let mut buffer = [0_u8; 512];
    let mut advertise_error_reported = false;
    let mut receive_error_reported = false;
    let mut incoming_failure_reported = false;

    loop {
        tokio::select! {
            () = runtime.stopped() => break,
            _ = advertisements.tick() => {
                match discovery.send_to(&advertisement, discovery_target).await {
                    Ok(_) => advertise_error_reported = false,
                    Err(error) if !advertise_error_reported => {
                        runtime.interface_error(None, format!("could not advertise on the LAN: {error}"));
                        advertise_error_reported = true;
                    }
                    Err(_) => {}
                }
            }
            received = discovery.recv_from(&mut buffer) => {
                match received {
                    Ok((length, source)) => {
                        receive_error_reported = false;
                        if let Some(peer) = decode_advertisement(&buffer[..length])
                            && peer.public_key != local
                            && local < peer.public_key
                        {
                            remember_peer(
                                &mut peers,
                                peer,
                                source,
                                &config,
                            );
                        }
                    }
                    Err(error) if !receive_error_reported => {
                        runtime.interface_error(None, format!("could not receive LAN discovery: {error}"));
                        receive_error_reported = true;
                    }
                    Err(_) => {}
                }
            }
            _ = maintenance.tick() => {
                maintain_peers(
                    &mut peers,
                    &mut connections,
                    &endpoint,
                    &runtime,
                    &config,
                );
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                if connections.len() >= config.maximum_peers {
                    incoming.refuse();
                    continue;
                }
                let runtime = runtime.clone();
                let link = config.link.clone();
                connections.spawn(async move {
                    let result = run_incoming_connection(incoming, runtime, link).await;
                    ConnectionOutcome {
                        peer: None,
                        established: result.is_ok(),
                        error: result.err().map(|error| error.to_string()),
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                match result {
                    Ok(outcome) => finish_connection(
                        &mut peers,
                        outcome,
                        &runtime,
                        &config,
                        &mut incoming_failure_reported,
                    ),
                    Err(error) if !error.is_cancelled() && !incoming_failure_reported => {
                        runtime.interface_error(
                            None,
                            format!("LAN QUIC connection task failed: {error}"),
                        );
                        incoming_failure_reported = true;
                    }
                    Err(_) => {}
                }
            }
        }
    }

    endpoint.close(0_u8.into(), b"interface stopped");
    while connections.join_next().await.is_some() {}
}

fn remember_peer(
    peers: &mut BTreeMap<PublicKey, Peer>,
    advertisement: Advertisement,
    source: SocketAddr,
    config: &QuicLanConfig,
) {
    let SocketAddr::V6(source) = source else {
        return;
    };
    let scope_id = if source.scope_id() == 0 {
        config.interface_index
    } else {
        source.scope_id()
    };
    let address = SocketAddr::V6(SocketAddrV6::new(
        *source.ip(),
        advertisement.quic_port,
        source.flowinfo(),
        scope_id,
    ));
    let now = Instant::now();
    let duplicate = peers.iter().any(|(&public_key, peer)| {
        public_key != advertisement.public_key && peer.address == address
    });
    if duplicate {
        return;
    }
    if let Some(peer) = peers.get_mut(&advertisement.public_key) {
        if peer.active && peer.address != address {
            return;
        }
        peer.address = address;
        peer.last_seen = now;
    } else if peers.len() < config.maximum_peers {
        peers.insert(
            advertisement.public_key,
            Peer {
                address,
                last_seen: now,
                next_attempt: now + reconnect_delay(config.reconnect.initial_delay),
                reconnect_delay: config.reconnect.initial_delay,
                active: false,
                failure_reported: false,
            },
        );
    }
}

fn maintain_peers(
    peers: &mut BTreeMap<PublicKey, Peer>,
    connections: &mut JoinSet<ConnectionOutcome>,
    endpoint: &Endpoint,
    runtime: &RuntimeHandle,
    config: &QuicLanConfig,
) {
    let now = Instant::now();
    peers
        .retain(|_, peer| peer.active || now.duration_since(peer.last_seen) <= config.peer_timeout);
    let ready = peers
        .iter()
        .filter_map(|(&public_key, peer)| {
            (!peer.active && peer.next_attempt <= now).then_some((public_key, peer.address))
        })
        .collect::<Vec<_>>();
    for (public_key, address) in ready {
        if connections.len() >= config.maximum_peers {
            break;
        }
        peers
            .get_mut(&public_key)
            .expect("ready peers remain present")
            .active = true;
        let endpoint = endpoint.clone();
        let runtime = runtime.clone();
        let link = config.link.clone();
        connections.spawn(async move {
            let (established, error) =
                match run_outgoing_connection(&endpoint, address, runtime, link).await {
                    Ok(()) => (true, None),
                    Err(error) => (false, Some(format!("{address}: {error}"))),
                };
            ConnectionOutcome {
                peer: Some(public_key),
                established,
                error,
            }
        });
    }
}

fn finish_connection(
    peers: &mut BTreeMap<PublicKey, Peer>,
    outcome: ConnectionOutcome,
    runtime: &RuntimeHandle,
    config: &QuicLanConfig,
    incoming_failure_reported: &mut bool,
) {
    let Some(public_key) = outcome.peer else {
        if outcome.established {
            *incoming_failure_reported = false;
        } else if !*incoming_failure_reported && let Some(error) = outcome.error {
            runtime.interface_error(None, error);
            *incoming_failure_reported = true;
        }
        return;
    };
    let Some(peer) = peers.get_mut(&public_key) else {
        return;
    };
    peer.active = false;
    if outcome.established {
        peer.reconnect_delay = config.reconnect.initial_delay;
        peer.failure_reported = false;
    } else {
        if !peer.failure_reported
            && let Some(error) = outcome.error
        {
            runtime.interface_error(None, error);
            peer.failure_reported = true;
        }
        peer.reconnect_delay =
            increase_reconnect_delay(peer.reconnect_delay, config.reconnect.maximum_delay);
    }
    peer.next_attempt = Instant::now() + reconnect_delay(peer.reconnect_delay);
}

fn discovery_socket(config: &QuicLanConfig) -> Result<UdpSocket, QuicInterfaceError> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(QuicInterfaceError::Discovery)?;
    socket
        .set_only_v6(true)
        .map_err(QuicInterfaceError::Discovery)?;
    socket
        .set_reuse_address(true)
        .map_err(QuicInterfaceError::Discovery)?;
    socket
        .set_multicast_if_v6(config.interface_index)
        .map_err(QuicInterfaceError::Discovery)?;
    let bind = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        config.discovery_address.port(),
        0,
        0,
    ));
    socket
        .bind(&bind.into())
        .map_err(QuicInterfaceError::Discovery)?;
    socket
        .join_multicast_v6(config.discovery_address.ip(), config.interface_index)
        .map_err(QuicInterfaceError::Discovery)?;
    socket
        .set_nonblocking(true)
        .map_err(QuicInterfaceError::Discovery)?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket).map_err(QuicInterfaceError::Discovery)
}

struct Advertisement {
    public_key: PublicKey,
    quic_port: u16,
}

fn encode_advertisement(public_key: PublicKey, quic_port: u16) -> [u8; ADVERTISEMENT_LEN] {
    let mut output = [0; ADVERTISEMENT_LEN];
    output[..ADVERTISEMENT_MAGIC.len()].copy_from_slice(ADVERTISEMENT_MAGIC);
    output[ADVERTISEMENT_MAGIC.len()] = ADVERTISEMENT_VERSION;
    let port_start = ADVERTISEMENT_MAGIC.len() + 1;
    output[port_start..port_start + size_of::<u16>()].copy_from_slice(&quic_port.to_be_bytes());
    output[port_start + size_of::<u16>()..].copy_from_slice(&public_key.to_bytes());
    output
}

fn decode_advertisement(input: &[u8]) -> Option<Advertisement> {
    if input.len() != ADVERTISEMENT_LEN
        || &input[..ADVERTISEMENT_MAGIC.len()] != ADVERTISEMENT_MAGIC
        || input[ADVERTISEMENT_MAGIC.len()] != ADVERTISEMENT_VERSION
    {
        return None;
    }
    let port_start = ADVERTISEMENT_MAGIC.len() + 1;
    let quic_port = u16::from_be_bytes(
        input[port_start..port_start + size_of::<u16>()]
            .try_into()
            .ok()?,
    );
    if quic_port == 0 {
        return None;
    }
    let key_bytes: [u8; PublicKey::LEN] = input[port_start + size_of::<u16>()..].try_into().ok()?;
    let public_key = PublicKey::try_from(key_bytes).ok()?;
    Some(Advertisement {
        public_key,
        quic_port,
    })
}

const fn default_discovery_address() -> SocketAddrV6 {
    SocketAddrV6::new(DEFAULT_DISCOVERY_GROUP, DEFAULT_DISCOVERY_PORT, 0, 0)
}

const fn default_bind_address() -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)
}

const fn default_advertisement_interval() -> Duration {
    DEFAULT_ADVERTISEMENT_INTERVAL
}

const fn default_peer_timeout() -> Duration {
    DEFAULT_PEER_TIMEOUT
}

const fn default_maximum_peers() -> usize {
    DEFAULT_MAXIMUM_PEERS
}
