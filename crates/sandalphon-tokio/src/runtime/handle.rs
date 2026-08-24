#[cfg(any(feature = "interface-memory", feature = "interface-quic"))]
use sandalphon_core::core::LinkId;
use sandalphon_core::{
    core::CoreOperationError,
    crypto::{CryptoError, PublicKey, SessionId},
    link::LinkFrame,
    session::ProtocolId,
    storage::StorageError,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use super::link::{AttachedLink, LinkConfig};

#[derive(Debug, Error)]
pub enum RuntimeHandleError {
    #[error("the Sandalphon runtime has stopped")]
    Stopped,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("storage capacity exceeded: {resource}")]
    Storage { resource: &'static str },
}

impl From<StorageError> for RuntimeHandleError {
    fn from(error: StorageError) -> Self {
        Self::Storage {
            resource: error.resource,
        }
    }
}

impl From<CoreOperationError> for RuntimeHandleError {
    fn from(error: CoreOperationError) -> Self {
        match error {
            CoreOperationError::Crypto(error) => error.into(),
            CoreOperationError::Storage(error) => error.into(),
        }
    }
}

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(super) commands: mpsc::Sender<Command>,
}

impl RuntimeHandle {
    pub async fn listen(&self, protocol: ProtocolId) -> Result<bool, RuntimeHandleError> {
        self.request(|response| Command::Listen { protocol, response })
            .await?
            .map_err(Into::into)
    }

    pub async fn unlisten(&self, protocol: ProtocolId) -> Result<bool, RuntimeHandleError> {
        self.request(|response| Command::Unlisten { protocol, response })
            .await
    }

    pub async fn initiate(
        &self,
        destination: PublicKey,
        protocol: ProtocolId,
        data: Vec<u8>,
    ) -> Result<SessionId, RuntimeHandleError> {
        self.request(|response| Command::Initiate {
            destination,
            protocol,
            data,
            response,
        })
        .await?
        .map_err(Into::into)
    }

    pub async fn accept(
        &self,
        session: SessionId,
        data: Vec<u8>,
    ) -> Result<(), RuntimeHandleError> {
        self.request(|response| Command::Accept {
            session,
            data,
            response,
        })
        .await?
        .map_err(Into::into)
    }

    pub async fn reject(&self, session: SessionId) -> Result<bool, RuntimeHandleError> {
        self.request(|response| Command::Reject { session, response })
            .await
    }

    pub async fn send(
        &self,
        session: SessionId,
        payload: Vec<u8>,
    ) -> Result<(), RuntimeHandleError> {
        self.request(|response| Command::Send {
            session,
            payload,
            response,
        })
        .await?
        .map_err(Into::into)
    }

    pub async fn remove_session(&self, session: SessionId) -> Result<bool, RuntimeHandleError> {
        self.request(|response| Command::RemoveSession { session, response })
            .await
    }

    pub async fn max_payload_len(
        &self,
        destination: PublicKey,
    ) -> Result<Option<usize>, RuntimeHandleError> {
        self.request(|response| Command::MaxPayloadLen {
            destination,
            response,
        })
        .await
    }

    pub async fn request_routes(&self, destination: PublicKey) -> Result<(), RuntimeHandleError> {
        self.request(|response| Command::RequestRoutes {
            destination,
            response,
        })
        .await
    }

    pub async fn shutdown(&self) -> Result<(), RuntimeHandleError> {
        self.request(|response| Command::Shutdown { response })
            .await
    }

    pub fn is_stopped(&self) -> bool {
        self.commands.is_closed()
    }

    async fn request<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, RuntimeHandleError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(command(response))
            .await
            .map_err(|_| RuntimeHandleError::Stopped)?;
        receiver.await.map_err(|_| RuntimeHandleError::Stopped)
    }

    #[cfg_attr(
        not(any(feature = "interface-memory", feature = "interface-quic")),
        allow(dead_code)
    )]
    pub(crate) async fn attach(
        &self,
        config: LinkConfig,
        outgoing: mpsc::Sender<LinkFrame>,
        completion: oneshot::Sender<Result<(), String>>,
    ) -> Result<AttachedLink, RuntimeHandleError> {
        self.request(|response| Command::Attach {
            config,
            outgoing,
            completion,
            response,
        })
        .await?
        .map_err(Into::into)
    }

    #[cfg(any(feature = "interface-memory", feature = "interface-quic"))]
    pub(crate) fn interface_error(&self, link: Option<LinkId>, message: String) {
        let _ = self
            .commands
            .try_send(Command::InterfaceError { link, message });
    }

    #[cfg(feature = "interface-quic")]
    pub(crate) async fn stopped(&self) {
        self.commands.closed().await;
    }
}

pub(super) enum Command {
    Listen {
        protocol: ProtocolId,
        response: oneshot::Sender<Result<bool, StorageError>>,
    },
    Unlisten {
        protocol: ProtocolId,
        response: oneshot::Sender<bool>,
    },
    Initiate {
        destination: PublicKey,
        protocol: ProtocolId,
        data: Vec<u8>,
        response: oneshot::Sender<Result<SessionId, CoreOperationError>>,
    },
    Accept {
        session: SessionId,
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), CryptoError>>,
    },
    Reject {
        session: SessionId,
        response: oneshot::Sender<bool>,
    },
    Send {
        session: SessionId,
        payload: Vec<u8>,
        response: oneshot::Sender<Result<(), CryptoError>>,
    },
    RemoveSession {
        session: SessionId,
        response: oneshot::Sender<bool>,
    },
    MaxPayloadLen {
        destination: PublicKey,
        response: oneshot::Sender<Option<usize>>,
    },
    RequestRoutes {
        destination: PublicKey,
        response: oneshot::Sender<()>,
    },
    #[cfg_attr(
        not(any(feature = "interface-memory", feature = "interface-quic")),
        allow(dead_code)
    )]
    Attach {
        config: LinkConfig,
        outgoing: mpsc::Sender<LinkFrame>,
        completion: oneshot::Sender<Result<(), String>>,
        response: oneshot::Sender<Result<AttachedLink, StorageError>>,
    },
    #[cfg(any(feature = "interface-memory", feature = "interface-quic"))]
    InterfaceError {
        link: Option<LinkId>,
        message: String,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}
