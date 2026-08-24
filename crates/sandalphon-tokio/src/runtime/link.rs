use std::time::Duration;

use getrandom::SysRng;
use rand_core::UnwrapErr;
use sandalphon_core::{
    core::{LinkAction, LinkId},
    link::{Gossip, LinkEffect, LinkFrame, LinkManager},
    network::TransitGroupId,
    storage::BTreeStorage,
};
use tokio::sync::{mpsc, oneshot};

use super::{handle::RuntimeHandleError, now_ms};

#[derive(Clone)]
#[cfg_attr(
    not(any(feature = "interface-memory", feature = "interface-quic")),
    allow(dead_code)
)]
pub(crate) struct AttachedLink {
    id: LinkId,
    inputs: mpsc::Sender<LinkInput>,
}

#[cfg_attr(
    not(any(feature = "interface-memory", feature = "interface-quic")),
    allow(dead_code)
)]
impl AttachedLink {
    pub(crate) fn id(&self) -> LinkId {
        self.id
    }

    pub(crate) async fn received(&self, frame: LinkFrame) -> Result<(), RuntimeHandleError> {
        self.inputs
            .send(LinkInput::Received(frame))
            .await
            .map_err(|_| RuntimeHandleError::Stopped)
    }

    pub(crate) async fn detach(&self) {
        let _ = self.inputs.send(LinkInput::Close).await;
    }
}

pub(super) struct LinkHandle {
    pub(super) actions: mpsc::Sender<Vec<LinkAction>>,
    pub(super) shutdown: oneshot::Sender<Result<(), String>>,
}

pub(crate) struct LinkConfig {
    pub mtu: u16,
    pub minimum_mtu: u16,
    pub edge_lifetime_ms: u64,
    pub incomplete_limit: usize,
    pub transit_groups: Vec<TransitGroupId>,
}

pub(super) enum LinkInput {
    #[cfg_attr(
        not(any(feature = "interface-memory", feature = "interface-quic")),
        allow(dead_code)
    )]
    Received(LinkFrame),
    #[cfg_attr(
        not(any(feature = "interface-memory", feature = "interface-quic")),
        allow(dead_code)
    )]
    Close,
}

pub(super) enum LinkEvent {
    Effect { link: LinkId, effect: LinkEffect },
    Stopped { link: LinkId },
}

pub(super) struct LinkChannels {
    pub(super) attached: AttachedLink,
    pub(super) inputs: mpsc::Receiver<LinkInput>,
    pub(super) action_sender: mpsc::Sender<Vec<LinkAction>>,
    pub(super) actions: mpsc::Receiver<Vec<LinkAction>>,
}

pub(super) fn channels(link: LinkId) -> LinkChannels {
    let (input_tx, input_rx) = mpsc::channel(super::LINK_CAPACITY);
    let (action_tx, action_rx) = mpsc::channel(super::LINK_CAPACITY);
    LinkChannels {
        attached: AttachedLink {
            id: link,
            inputs: input_tx,
        },
        inputs: input_rx,
        action_sender: action_tx,
        actions: action_rx,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_link(
    link: LinkId,
    mut manager: LinkManager<BTreeStorage>,
    mut inputs: mpsc::Receiver<LinkInput>,
    mut actions: mpsc::Receiver<Vec<LinkAction>>,
    core_events: mpsc::Sender<LinkEvent>,
    outgoing: mpsc::Sender<LinkFrame>,
    transport_completion: oneshot::Sender<Result<(), String>>,
    mut runtime_shutdown: oneshot::Receiver<Result<(), String>>,
    tick_interval: Duration,
) {
    let mut tick = tokio::time::interval(tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut error = dispatch_link_effects(link, [manager.announce()], &core_events, &outgoing)
        .await
        .err();

    while error.is_none() {
        let effects = tokio::select! {
            outcome = &mut runtime_shutdown => {
                if let Ok(Err(message)) = outcome {
                    error = Some(message);
                }
                break;
            },
            _ = tick.tick() => manager.expire(now_ms()),
            input = inputs.recv() => {
                match input {
                    Some(LinkInput::Received(frame)) => {
                        manager.receive(frame, now_ms(), &mut UnwrapErr(SysRng))
                    }
                    Some(LinkInput::Close) | None => break,
                }
            }
            batch = actions.recv() => {
                let Some(batch) = batch else {
                    break;
                };
                let mut effects = Vec::with_capacity(batch.len());
                let mut route_chunks_missing = false;
                for action in batch {
                    match action {
                        LinkAction::Transmit { frame } => {
                            effects.push(LinkEffect::Transmit { frame });
                        }
                        LinkAction::Send { edge, datagram } => {
                            effects.push(manager.send(edge, datagram));
                        }
                        LinkAction::Gossip { edge, gossip } => {
                            match gossip {
                                Gossip::Route(root) => {
                                    if !route_chunks_missing {
                                        effects.push(manager.gossip(edge, Gossip::Route(root)));
                                    }
                                    route_chunks_missing = false;
                                }
                                gossip => {
                                    let chunk = matches!(gossip, Gossip::PathChunk(_));
                                    let effect = manager.gossip(edge, gossip);
                                    if chunk && matches!(effect, LinkEffect::Capacity { .. }) {
                                        route_chunks_missing = true;
                                    }
                                    effects.push(effect);
                                }
                            }
                        }
                        LinkAction::RejectEdge { edge } => {
                            manager.reject_edge(edge);
                        }
                    }
                }
                effects
            }
        };
        error = dispatch_link_effects(link, effects, &core_events, &outgoing)
            .await
            .err();
    }

    if error.is_none() {
        error = dispatch_link_effects(link, manager.close(), &core_events, &outgoing)
            .await
            .err();
    }
    let _ = transport_completion.send(error.clone().map_or(Ok(()), Err));
    let _ = core_events.send(LinkEvent::Stopped { link }).await;
}

async fn dispatch_link_effects(
    link: LinkId,
    effects: impl IntoIterator<Item = LinkEffect>,
    core_events: &mpsc::Sender<LinkEvent>,
    outgoing: &mpsc::Sender<LinkFrame>,
) -> Result<(), String> {
    for effect in effects {
        match effect {
            LinkEffect::Transmit { frame } => {
                outgoing.try_send(frame).map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        "outgoing link frame queue is full".to_owned()
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        "link transport writer has stopped".to_owned()
                    }
                })?;
            }
            effect => {
                core_events
                    .send(LinkEvent::Effect { link, effect })
                    .await
                    .map_err(|_| "Sandalphon runtime has stopped".to_owned())?;
            }
        }
    }
    Ok(())
}
