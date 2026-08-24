use sandalphon_core::{
    core::{CoreError, LinkId},
    crypto::{PublicKey, SessionId},
    session::ProtocolId,
};
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    LinkAttached {
        link: LinkId,
    },
    LinkDetached {
        link: LinkId,
    },
    Incoming {
        session: SessionId,
        peer: PublicKey,
        protocol: ProtocolId,
        data: Vec<u8>,
    },
    Established {
        session: SessionId,
        peer: PublicKey,
        protocol: ProtocolId,
        data: Vec<u8>,
    },
    Deliver {
        session: SessionId,
        peer: PublicKey,
        protocol: ProtocolId,
        payload: Vec<u8>,
    },
    CoreError(CoreError),
    InterfaceError {
        link: Option<LinkId>,
        message: String,
    },
    EventQueueOverflow,
}

pub struct RuntimeEvents {
    pub(super) receiver: mpsc::Receiver<RuntimeEvent>,
}

impl RuntimeEvents {
    pub async fn recv(&mut self) -> Option<RuntimeEvent> {
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Result<RuntimeEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}
