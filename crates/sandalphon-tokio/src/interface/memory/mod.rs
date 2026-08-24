use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sandalphon_core::{link::LinkFrame, network::TransitGroupId};
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};

use crate::{RuntimeHandle, RuntimeHandleError, interface::Interface, runtime::LinkConfig};

const DEFAULT_MTU: u16 = 16 * 1024;
const DEFAULT_MINIMUM_MTU: u16 = 1_200;
const DEFAULT_INCOMPLETE_LIMIT: usize = 64;
const DEFAULT_OUTGOING_CAPACITY: usize = 64;
const DEFAULT_NETWORK_CAPACITY: usize = 1_024;
const DEFAULT_EDGE_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const MINIMUM_MTU: u16 = 26;

#[derive(Debug, Clone)]
pub struct MemoryLinkConfig {
    pub mtu: u16,
    pub minimum_mtu: u16,
    pub edge_lifetime: Duration,
    pub incomplete_limit: usize,
    pub outgoing_capacity: usize,
    pub transit_groups: Vec<TransitGroupId>,
}

impl Default for MemoryLinkConfig {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            minimum_mtu: DEFAULT_MINIMUM_MTU,
            edge_lifetime: DEFAULT_EDGE_LIFETIME,
            incomplete_limit: DEFAULT_INCOMPLETE_LIMIT,
            outgoing_capacity: DEFAULT_OUTGOING_CAPACITY,
            transit_groups: Vec::new(),
        }
    }
}

impl MemoryLinkConfig {
    fn validate(&self) -> Result<(), MemoryInterfaceError> {
        if self.mtu <= self.minimum_mtu {
            return Err(MemoryInterfaceError::InvalidConfig(
                "mtu must be greater than minimum_mtu",
            ));
        }
        if self.mtu < MINIMUM_MTU {
            return Err(MemoryInterfaceError::InvalidConfig(
                "mtu is smaller than Sandalphon's link framing overhead",
            ));
        }
        if self.incomplete_limit == 0 {
            return Err(MemoryInterfaceError::InvalidConfig(
                "incomplete_limit must be nonzero",
            ));
        }
        if self.edge_lifetime.is_zero() {
            return Err(MemoryInterfaceError::InvalidConfig(
                "edge_lifetime must be nonzero",
            ));
        }
        if self.outgoing_capacity == 0 {
            return Err(MemoryInterfaceError::InvalidConfig(
                "outgoing_capacity must be nonzero",
            ));
        }
        Ok(())
    }

    fn runtime_config(&self) -> LinkConfig {
        LinkConfig {
            mtu: self.mtu,
            minimum_mtu: self.minimum_mtu,
            edge_lifetime_ms: u64::try_from(self.edge_lifetime.as_millis()).unwrap_or(u64::MAX),
            incomplete_limit: self.incomplete_limit,
            transit_groups: self.transit_groups.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryNetwork {
    inner: Arc<MemoryNetworkInner>,
}

#[derive(Debug)]
struct MemoryNetworkInner {
    next_member: AtomicU64,
    frames: broadcast::Sender<(u64, LinkFrame)>,
}

impl MemoryNetwork {
    pub fn new(capacity: usize) -> Result<Self, MemoryInterfaceError> {
        if capacity == 0 {
            return Err(MemoryInterfaceError::InvalidConfig(
                "network capacity must be nonzero",
            ));
        }
        let (frames, _) = broadcast::channel(capacity);
        Ok(Self {
            inner: Arc::new(MemoryNetworkInner {
                next_member: AtomicU64::new(0),
                frames,
            }),
        })
    }

    fn subscribe(&self) -> (u64, broadcast::Receiver<(u64, LinkFrame)>) {
        (
            self.inner.next_member.fetch_add(1, Ordering::Relaxed),
            self.inner.frames.subscribe(),
        )
    }
}

impl Default for MemoryNetwork {
    fn default() -> Self {
        Self::new(DEFAULT_NETWORK_CAPACITY).expect("default network capacity is nonzero")
    }
}

#[derive(Debug, Clone)]
pub struct MemoryInterfaceConfig {
    pub network: MemoryNetwork,
    pub link: MemoryLinkConfig,
}

impl MemoryInterfaceConfig {
    pub fn new(network: MemoryNetwork) -> Self {
        Self {
            network,
            link: MemoryLinkConfig::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum MemoryInterfaceError {
    #[error("invalid in-memory interface configuration: {0}")]
    InvalidConfig(&'static str),
    #[error(transparent)]
    Runtime(#[from] RuntimeHandleError),
}

pub struct MemoryInterface {
    shutdown: Option<oneshot::Sender<()>>,
    _task: JoinHandle<()>,
}

impl MemoryInterface {
    pub async fn pair(
        first: RuntimeHandle,
        second: RuntimeHandle,
    ) -> Result<(Self, Self), MemoryInterfaceError> {
        Self::pair_with(
            (first, MemoryLinkConfig::default()),
            (second, MemoryLinkConfig::default()),
        )
        .await
    }

    pub async fn pair_with(
        first: (RuntimeHandle, MemoryLinkConfig),
        second: (RuntimeHandle, MemoryLinkConfig),
    ) -> Result<(Self, Self), MemoryInterfaceError> {
        let network = MemoryNetwork::default();
        let first = Self::new(
            first.0,
            MemoryInterfaceConfig {
                network: network.clone(),
                link: first.1,
            },
        )
        .await?;
        let second = Self::new(
            second.0,
            MemoryInterfaceConfig {
                network,
                link: second.1,
            },
        )
        .await?;
        Ok((first, second))
    }

    pub async fn group(
        members: impl IntoIterator<Item = RuntimeHandle>,
    ) -> Result<Vec<Self>, MemoryInterfaceError> {
        let network = MemoryNetwork::default();
        let mut interfaces = Vec::new();
        for runtime in members {
            interfaces.push(Self::new(runtime, MemoryInterfaceConfig::new(network.clone())).await?);
        }
        Ok(interfaces)
    }
}

impl Interface for MemoryInterface {
    type Config = MemoryInterfaceConfig;
    type Error = MemoryInterfaceError;

    async fn new(runtime: RuntimeHandle, config: Self::Config) -> Result<Self, Self::Error> {
        config.link.validate()?;
        let (member, received) = config.network.subscribe();
        let (outgoing, frames) = mpsc::channel(config.link.outgoing_capacity);
        let (runtime_completion, runtime_completion_signal) = oneshot::channel();
        let link = runtime
            .attach(config.link.runtime_config(), outgoing, runtime_completion)
            .await?;
        let (shutdown, shutdown_signal) = oneshot::channel();
        let task = tokio::spawn(run_interface(
            config.network,
            member,
            link,
            runtime,
            frames,
            received,
            runtime_completion_signal,
            shutdown_signal,
            config.link.edge_lifetime,
        ));
        Ok(Self {
            shutdown: Some(shutdown),
            _task: task,
        })
    }
}

impl Drop for MemoryInterface {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_interface(
    network: MemoryNetwork,
    member: u64,
    link: crate::runtime::AttachedLink,
    runtime: RuntimeHandle,
    mut outgoing: mpsc::Receiver<LinkFrame>,
    mut received: broadcast::Receiver<(u64, LinkFrame)>,
    runtime_completion: oneshot::Receiver<Result<(), String>>,
    interface_shutdown: oneshot::Receiver<()>,
    edge_lifetime: Duration,
) {
    let lifetime = tokio::time::sleep(edge_lifetime);
    tokio::pin!(lifetime);
    tokio::pin!(runtime_completion);
    tokio::pin!(interface_shutdown);

    loop {
        tokio::select! {
            () = &mut lifetime => break,
            outcome = &mut runtime_completion => {
                if let Ok(Err(message)) = outcome {
                    runtime.interface_error(Some(link.id()), message);
                }
                break;
            }
            _ = &mut interface_shutdown => break,
            frame = outgoing.recv() => {
                let Some(frame) = frame else {
                    break;
                };
                let _ = network.inner.frames.send((member, frame));
            }
            frame = received.recv() => {
                match frame {
                    Ok((source, frame)) if source != member => {
                        if link.received(frame).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        runtime.interface_error(
                            Some(link.id()),
                            format!("in-memory interface lagged by {skipped} frames"),
                        );
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    link.detach().await;
}
