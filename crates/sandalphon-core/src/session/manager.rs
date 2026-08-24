use alloc::{boxed::Box, vec, vec::Vec};

use rand_core::CryptoRng;

use crate::{
    crypto::{CryptoError, IkHandshake, NoiseSession, PrivateKey, PublicKey, SessionId},
    session::{Packet, ProtocolId, SessionEffect, SessionError},
    storage::{StorageError, StorageProvider, TableMap, TableSet},
};

const HANDSHAKE_CONTEXT: &[u8] = b"sandalphon/session/v1";

#[derive(Debug)]
pub(crate) enum SessionStartError {
    Crypto(CryptoError),
    Storage(StorageError),
}

impl From<CryptoError> for SessionStartError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<StorageError> for SessionStartError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

enum Session {
    Initiating {
        peer: PublicKey,
        protocol: ProtocolId,
        handshake: Box<IkHandshake>,
    },
    Incoming {
        peer: PublicKey,
        protocol: ProtocolId,
        handshake: Box<IkHandshake>,
    },
    Established {
        peer: PublicKey,
        protocol: ProtocolId,
        noise: NoiseSession,
    },
}

pub(crate) struct SessionManager<P: StorageProvider> {
    pub(super) private_key: PrivateKey,
    listeners: P::SessionListeners<ProtocolId>,
    sessions: P::SessionSessions<SessionId, Session>,
}

impl<P: StorageProvider> SessionManager<P> {
    pub(crate) fn new(private_key: PrivateKey) -> Self {
        Self {
            private_key,
            listeners: Default::default(),
            sessions: Default::default(),
        }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        self.private_key.public()
    }

    pub(crate) fn listen(&mut self, protocol: ProtocolId) -> Result<bool, StorageError> {
        self.listeners
            .try_insert(protocol)
            .map_err(|_| StorageError {
                resource: "session listeners",
            })
    }

    pub(crate) fn unlisten(&mut self, protocol: ProtocolId) -> bool {
        if !self.listeners.remove(&protocol) {
            return false;
        }
        self.sessions.retain(|_, session| {
            !matches!(
                session,
                Session::Incoming {
                    protocol: incoming,
                    ..
                } if *incoming == protocol
            )
        });
        true
    }

    pub(crate) fn is_listening(&self, protocol: ProtocolId) -> bool {
        self.listeners.contains(&protocol)
    }

    pub(crate) fn initiate<R: CryptoRng>(
        &mut self,
        destination: PublicKey,
        protocol: ProtocolId,
        data: &[u8],
        rng: &mut R,
    ) -> Result<(SessionId, SessionEffect), SessionStartError> {
        let mut payload = Vec::with_capacity(ProtocolId::LEN + data.len());
        payload.extend(protocol.to_bytes());
        payload.extend(data);
        let (handshake, message) = IkHandshake::initiate(
            self.private_key.clone(),
            destination,
            HANDSHAKE_CONTEXT,
            &payload,
            rng,
        )?;
        let session = handshake.session_id();
        if self.sessions.contains_key(&session) {
            return Err(StorageError {
                resource: "session identifiers",
            }
            .into());
        }
        self.sessions
            .try_insert(
                session,
                Session::Initiating {
                    peer: destination,
                    protocol,
                    handshake: Box::new(handshake),
                },
            )
            .map_err(|_| StorageError {
                resource: "sessions",
            })?;

        Ok((
            session,
            SessionEffect::Transmit {
                destination,
                packet: Packet::HandshakeInit { message },
            },
        ))
    }

    pub(crate) fn accept<R: CryptoRng>(
        &mut self,
        session: SessionId,
        data: &[u8],
        rng: &mut R,
    ) -> Result<SessionEffect, CryptoError> {
        if !self.sessions.contains_key(&session) {
            return Ok(SessionEffect::Error(SessionError::UnknownSession {
                session,
            }));
        }
        let Some(Session::Incoming {
            peer,
            protocol,
            handshake,
        }) = self.take_incoming(session)
        else {
            return Ok(SessionEffect::Error(SessionError::NotIncoming { session }));
        };
        let (message, noise) = (*handshake).write_response(data, rng)?;
        self.sessions.insert(
            session,
            Session::Established {
                peer,
                protocol,
                noise,
            },
        );

        Ok(SessionEffect::Transmit {
            destination: peer,
            packet: Packet::HandshakeResponse { session, message },
        })
    }

    pub(crate) fn reject(&mut self, session: SessionId) -> bool {
        self.take_incoming(session).is_some()
    }

    pub(crate) fn send(
        &mut self,
        session: SessionId,
        payload: &[u8],
    ) -> Result<SessionEffect, CryptoError> {
        if !self.sessions.contains_key(&session) {
            return Ok(SessionEffect::Error(SessionError::UnknownSession {
                session,
            }));
        }
        let Some(Session::Established { peer, noise, .. }) = self.sessions.get_mut(&session) else {
            return Ok(SessionEffect::Error(SessionError::NotEstablished {
                session,
            }));
        };
        let (sequence, ciphertext) = noise.seal(&session.0.to_le_bytes(), payload)?;

        Ok(SessionEffect::Transmit {
            destination: *peer,
            packet: Packet::Transport {
                session,
                sequence,
                ciphertext,
            },
        })
    }

    pub(crate) fn receive(&mut self, packet: Packet) -> Vec<SessionEffect> {
        match packet {
            Packet::HandshakeInit { message } => {
                let Ok((handshake, origin, payload)) =
                    IkHandshake::respond(&self.private_key, HANDSHAKE_CONTEXT, &message)
                else {
                    return Vec::new();
                };
                let Some((protocol, data)) = payload.split_at_checked(ProtocolId::LEN) else {
                    return Vec::new();
                };
                let protocol =
                    ProtocolId::from_bytes(protocol.try_into().expect("slice length was checked"));
                if !self.is_listening(protocol) {
                    return Vec::new();
                }
                let data = data.to_vec();
                let session = handshake.session_id();
                if self.sessions.contains_key(&session) {
                    return Vec::new();
                }
                if self
                    .sessions
                    .try_insert(
                        session,
                        Session::Incoming {
                            peer: origin,
                            protocol,
                            handshake: Box::new(handshake),
                        },
                    )
                    .is_err()
                {
                    return vec![SessionEffect::Error(SessionError::StorageFull {
                        resource: "sessions",
                    })];
                }

                vec![SessionEffect::Incoming {
                    session,
                    peer: origin,
                    protocol,
                    data,
                }]
            }
            Packet::HandshakeResponse { session, message } => {
                let Some(Session::Initiating {
                    peer,
                    protocol,
                    handshake,
                }) = self.take_initiating(session)
                else {
                    return Vec::new();
                };
                let Ok((payload, noise)) = (*handshake).read_response(&message) else {
                    return Vec::new();
                };
                self.sessions.insert(
                    session,
                    Session::Established {
                        peer,
                        protocol,
                        noise,
                    },
                );
                vec![SessionEffect::Established {
                    session,
                    peer,
                    protocol,
                    data: payload,
                }]
            }
            Packet::Transport {
                session,
                sequence,
                ciphertext,
            } => {
                let Some(Session::Established {
                    peer,
                    protocol,
                    noise,
                }) = self.sessions.get_mut(&session)
                else {
                    return Vec::new();
                };
                let Some(payload) = noise.open(sequence, &session.0.to_le_bytes(), &ciphertext)
                else {
                    return Vec::new();
                };

                vec![SessionEffect::Deliver {
                    session,
                    peer: *peer,
                    protocol: *protocol,
                    payload,
                }]
            }
        }
    }

    fn take_incoming(&mut self, session: SessionId) -> Option<Session> {
        matches!(self.sessions.get(&session), Some(Session::Incoming { .. }))
            .then(|| self.sessions.remove(&session))
            .flatten()
    }

    fn take_initiating(&mut self, session: SessionId) -> Option<Session> {
        matches!(
            self.sessions.get(&session),
            Some(Session::Initiating { .. })
        )
        .then(|| self.sessions.remove(&session))
        .flatten()
    }

    pub(crate) fn remove(&mut self, session: SessionId) -> bool {
        self.sessions.remove(&session).is_some()
    }
}
