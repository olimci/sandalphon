use alloc::vec::Vec;

use bytes::{Buf, BufMut};

use crate::{crypto::SessionId, session::Packet};

impl Packet {
    pub(crate) const TRANSPORT_OVERHEAD: usize = 1 + SessionId::LEN + size_of::<u32>() + 16;

    const HANDSHAKE_INIT: u8 = 0x00;
    const HANDSHAKE_RESPONSE: u8 = 0x01;
    const TRANSPORT: u8 = 0x02;

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        match self {
            Self::HandshakeInit { message } => {
                output.put_u8(Self::HANDSHAKE_INIT);
                output.put_slice(message);
            }
            Self::HandshakeResponse { session, message } => {
                output.put_u8(Self::HANDSHAKE_RESPONSE);
                output.put_u32_le(session.0);
                output.put_slice(message);
            }
            Self::Transport {
                session,
                sequence,
                ciphertext,
            } => {
                output.put_u8(Self::TRANSPORT);
                output.put_u32_le(session.0);
                output.put_u32_le(*sequence);
                output.put_slice(ciphertext);
            }
        }

        output
    }

    pub(crate) fn from_bytes(mut input: &[u8]) -> Option<Self> {
        match input.try_get_u8().ok()? {
            Self::HANDSHAKE_INIT if (96..=u16::MAX as usize).contains(&input.remaining()) => {
                Some(Self::HandshakeInit {
                    message: input.to_vec(),
                })
            }
            Self::HANDSHAKE_RESPONSE
                if (SessionId::LEN + 48..=SessionId::LEN + u16::MAX as usize)
                    .contains(&input.remaining()) =>
            {
                Some(Self::HandshakeResponse {
                    session: SessionId(input.try_get_u32_le().ok()?),
                    message: input.to_vec(),
                })
            }
            Self::TRANSPORT if input.remaining() >= SessionId::LEN + size_of::<u32>() + 16 => {
                Some(Self::Transport {
                    session: SessionId(input.try_get_u32_le().ok()?),
                    sequence: input.try_get_u32_le().ok()?,
                    ciphertext: input.to_vec(),
                })
            }
            _ => None,
        }
    }
}
