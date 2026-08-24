use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use getrandom::SysRng;
use rand_core::UnwrapErr;
use sandalphon_core::{
    core::{CoreEffect, CoreError, LinkAction, LinkId, SandalphonCore},
    crypto::PrivateKey,
    link::LinkManager,
    storage::BTreeStorage,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

mod events;
mod handle;
mod link;

pub use events::{RuntimeEvent, RuntimeEvents};
use handle::Command;
pub use handle::{RuntimeHandle, RuntimeHandleError};
#[cfg(any(feature = "interface-memory", feature = "interface-quic"))]
pub(crate) use link::{AttachedLink, LinkConfig};
use link::{LinkChannels, LinkEvent, LinkHandle, channels, run_link};

const COMMAND_CAPACITY: usize = 256;
const LINK_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub route_candidates: usize,
    pub tick_interval: Duration,
    pub event_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            route_candidates: 3,
            tick_interval: Duration::from_secs(1),
            event_capacity: 256,
        }
    }
}

pub struct Runtime {
    core: SandalphonCore<BTreeStorage>,
    private_key: PrivateKey,
    config: RuntimeConfig,
    commands: mpsc::Receiver<Command>,
    link_events: mpsc::Receiver<LinkEvent>,
    link_event_sender: mpsc::Sender<LinkEvent>,
    link_tasks: JoinSet<()>,
    events: mpsc::Sender<RuntimeEvent>,
    links: BTreeMap<LinkId, LinkHandle>,
    next_link: u64,
    event_queue_overflowed: bool,
}

impl Runtime {
    pub fn new(
        private_key: PrivateKey,
        config: RuntimeConfig,
    ) -> (Self, RuntimeHandle, RuntimeEvents) {
        assert!(config.route_candidates > 0);
        assert!(!config.tick_interval.is_zero());
        assert!(config.event_capacity > 0);
        assert!(config.event_capacity < usize::MAX);

        let core = SandalphonCore::new(private_key.clone(), config.route_candidates);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (link_event_tx, link_event_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(config.event_capacity + 1);

        (
            Self {
                core,
                private_key,
                config,
                commands: command_rx,
                link_events: link_event_rx,
                link_event_sender: link_event_tx,
                link_tasks: JoinSet::new(),
                events: event_tx,
                links: BTreeMap::new(),
                next_link: 0,
                event_queue_overflowed: false,
            },
            RuntimeHandle {
                commands: command_tx,
            },
            RuntimeEvents { receiver: event_rx },
        )
    }

    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(self.config.tick_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut shutdown_response = None;

        loop {
            tokio::select! {
                _ = tick.tick() => self.tick(),
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    if let Some(response) = self.handle_command(command) {
                        shutdown_response = Some(response);
                        break;
                    }
                }
                event = self.link_events.recv() => {
                    if let Some(event) = event {
                        self.handle_link_event(event);
                    }
                }
                _ = self.link_tasks.join_next(), if !self.link_tasks.is_empty() => {}
            }
            if self.event_queue_overflowed {
                break;
            }
        }

        let links = std::mem::take(&mut self.links);
        for (_, link) in links {
            let _ = link.shutdown.send(Ok(()));
        }
        while !self.link_tasks.is_empty() {
            tokio::select! {
                _ = self.link_tasks.join_next() => {}
                _ = self.link_events.recv() => {}
            }
        }
        if let Some(response) = shutdown_response {
            let _ = response.send(());
        }
    }

    fn handle_command(&mut self, command: Command) -> Option<oneshot::Sender<()>> {
        match command {
            Command::Listen { protocol, response } => {
                let _ = response.send(self.core.listen(protocol));
            }
            Command::Unlisten { protocol, response } => {
                let _ = response.send(self.core.unlisten(protocol));
            }
            Command::Initiate {
                destination,
                protocol,
                data,
                response,
            } => {
                let result =
                    self.core
                        .initiate(destination, protocol, &data, &mut UnwrapErr(SysRng));
                match result {
                    Ok((session, effects)) => {
                        self.process_core_effects(effects);
                        let _ = response.send(Ok(session));
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
            Command::Accept {
                session,
                data,
                response,
            } => {
                let result = self.core.accept(session, &data, &mut UnwrapErr(SysRng));
                match result {
                    Ok(effects) => {
                        self.process_core_effects(effects);
                        let _ = response.send(Ok(()));
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
            Command::Reject { session, response } => {
                let _ = response.send(self.core.reject(session));
            }
            Command::Send {
                session,
                payload,
                response,
            } => {
                let result = self.core.send(session, &payload);
                match result {
                    Ok(effects) => {
                        self.process_core_effects(effects);
                        let _ = response.send(Ok(()));
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
            Command::RemoveSession { session, response } => {
                let _ = response.send(self.core.remove_session(session));
            }
            Command::MaxPayloadLen {
                destination,
                response,
            } => {
                let _ = response.send(self.core.max_payload_len(destination));
            }
            Command::RequestRoutes {
                destination,
                response,
            } => {
                let effects = self.core.request_routes(destination);
                self.process_core_effects(effects);
                let _ = response.send(());
            }
            Command::Attach {
                config,
                outgoing,
                completion,
                response,
            } => {
                let link = self.allocate_link();
                if let Err(error) = self
                    .core
                    .set_link_transit_groups(link, config.transit_groups.iter().copied())
                {
                    let _ = response.send(Err(error));
                    return None;
                }
                let manager = LinkManager::new(
                    self.private_key.clone(),
                    config.mtu,
                    config.minimum_mtu,
                    now_ms().saturating_add(config.edge_lifetime_ms),
                    config.incomplete_limit,
                    &mut UnwrapErr(SysRng),
                );
                let LinkChannels {
                    attached,
                    inputs,
                    action_sender,
                    actions,
                } = channels(link);
                let (link_shutdown_tx, link_shutdown_rx) = oneshot::channel();
                self.link_tasks.spawn(run_link(
                    link,
                    manager,
                    inputs,
                    actions,
                    self.link_event_sender.clone(),
                    outgoing,
                    completion,
                    link_shutdown_rx,
                    self.config.tick_interval,
                ));
                self.links.insert(
                    link,
                    LinkHandle {
                        actions: action_sender,
                        shutdown: link_shutdown_tx,
                    },
                );
                self.emit(RuntimeEvent::LinkAttached { link });
                let _ = response.send(Ok(attached));
            }
            #[cfg(any(feature = "interface-memory", feature = "interface-quic"))]
            Command::InterfaceError { link, message } => {
                self.emit(RuntimeEvent::InterfaceError { link, message });
            }
            Command::Shutdown { response } => {
                return Some(response);
            }
        }
        None
    }

    fn allocate_link(&mut self) -> LinkId {
        let link = LinkId(self.next_link);
        self.next_link = self
            .next_link
            .checked_add(1)
            .expect("runtime exhausted all link identifiers");
        link
    }

    fn handle_link_event(&mut self, event: LinkEvent) {
        match event {
            LinkEvent::Effect { link, effect } => {
                if self.links.contains_key(&link) {
                    let effects = self.core.link_effect(link, effect, now_ms());
                    self.process_core_effects(effects);
                }
            }
            LinkEvent::Stopped { link } => {
                self.close_link(link);
            }
        }
    }

    fn process_core_effects(&mut self, effects: impl IntoIterator<Item = CoreEffect>) {
        let mut link_actions = BTreeMap::<LinkId, Vec<LinkAction>>::new();
        for effect in effects {
            match effect {
                CoreEffect::Link { link, action } => {
                    if !self.links.contains_key(&link) {
                        self.emit(RuntimeEvent::CoreError(CoreError::UnknownEdge {
                            edge: match action {
                                LinkAction::Send { edge, .. }
                                | LinkAction::Gossip { edge, .. }
                                | LinkAction::RejectEdge { edge } => edge,
                                LinkAction::Transmit { .. } => continue,
                            },
                        }));
                        continue;
                    }
                    link_actions.entry(link).or_default().push(action);
                }
                CoreEffect::Incoming {
                    session,
                    peer,
                    protocol,
                    data,
                } => self.emit(RuntimeEvent::Incoming {
                    session,
                    peer,
                    protocol,
                    data,
                }),
                CoreEffect::Established {
                    session,
                    peer,
                    protocol,
                    data,
                } => self.emit(RuntimeEvent::Established {
                    session,
                    peer,
                    protocol,
                    data,
                }),
                CoreEffect::Deliver {
                    session,
                    peer,
                    protocol,
                    payload,
                } => self.emit(RuntimeEvent::Deliver {
                    session,
                    peer,
                    protocol,
                    payload,
                }),
                CoreEffect::Error(error) => self.emit(RuntimeEvent::CoreError(error)),
            }
        }
        for (link, actions) in link_actions {
            let error = self
                .links
                .get(&link)
                .and_then(|active| active.actions.try_send(actions).err());
            if let Some(error) = error {
                let message = match error {
                    mpsc::error::TrySendError::Full(_) => "link action queue is full",
                    mpsc::error::TrySendError::Closed(_) => "link task has stopped",
                };
                self.fail_link(link, message.to_owned());
            }
        }
    }

    fn close_link(&mut self, link: LinkId) {
        self.finish_link(link, Ok(()));
    }

    fn fail_link(&mut self, link: LinkId, message: String) {
        self.finish_link(link, Err(message));
    }

    fn finish_link(&mut self, link: LinkId, outcome: Result<(), String>) {
        if let Some(active) = self.links.remove(&link) {
            let _ = active.shutdown.send(outcome);
            self.core.remove_link(link);
            self.emit(RuntimeEvent::LinkDetached { link });
        }
    }

    fn tick(&mut self) {
        let effects = self.core.tick(now_ms());
        self.process_core_effects(effects);
    }

    fn emit(&mut self, event: RuntimeEvent) {
        if self.event_queue_overflowed {
            return;
        }
        if self.events.capacity() <= 1 {
            let _ = self.events.try_send(RuntimeEvent::EventQueueOverflow);
            self.event_queue_overflowed = true;
            return;
        }
        let _ = self.events.try_send(event);
    }
}

fn now_ms() -> u64 {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(milliseconds).unwrap_or(u64::MAX)
}
