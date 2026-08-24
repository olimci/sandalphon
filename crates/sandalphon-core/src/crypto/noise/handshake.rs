use alloc::vec::Vec;

use rand_core::CryptoRng;

use crate::crypto::{
    CryptoError, PrivateKey, PublicKey,
    noise::{NoiseSession, SessionId, Window, symmetric::SymmetricState},
};

pub(crate) enum IkHandshake {
    AwaitingResponse {
        symmetric: SymmetricState,
        s: PrivateKey,
        e: PrivateKey,
    },
    Responding {
        symmetric: SymmetricState,
        rs: PublicKey,
        re: PublicKey,
    },
}

impl IkHandshake {
    pub(crate) fn session_id(&self) -> SessionId {
        SessionId(u32::from_le_bytes(
            match self {
                Self::AwaitingResponse { symmetric, .. } | Self::Responding { symmetric, .. } => {
                    symmetric.get_handshake_hash()
                }
            }[..SessionId::LEN]
                .try_into()
                .expect("Noise handshake hashes are 32 bytes"),
        ))
    }

    pub(crate) fn edge_salt(&self) -> [u8; 16] {
        match self {
            Self::AwaitingResponse { symmetric, .. } | Self::Responding { symmetric, .. } => {
                symmetric.get_handshake_hash()[..16].try_into().unwrap()
            }
        }
    }

    pub(crate) fn initiate<R: CryptoRng>(
        s: PrivateKey,
        rs: PublicKey,
        prologue: &[u8],
        payload: &[u8],
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        if payload.len() > u16::MAX as usize - 96 {
            return Err(CryptoError::InvalidNoiseHandshake);
        }

        let mut symmetric = SymmetricState::new();
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(&rs.to_bytes());

        let e = PrivateKey::generate(rng);
        let mut message = Vec::with_capacity(96 + payload.len());
        message.extend(e.public().to_bytes());
        symmetric.mix_hash(&message);
        symmetric.mix_key(e.diffie_hellman(&rs).as_ref());
        message.extend(symmetric.encrypt_and_hash(&s.public().to_bytes())?);
        symmetric.mix_key(s.diffie_hellman(&rs).as_ref());
        message.extend(symmetric.encrypt_and_hash(payload)?);

        Ok((Self::AwaitingResponse { symmetric, s, e }, message))
    }

    pub(crate) fn respond(
        s: &PrivateKey,
        prologue: &[u8],
        message: &[u8],
    ) -> Result<(Self, PublicKey, Vec<u8>), CryptoError> {
        if !(96..=u16::MAX as usize).contains(&message.len()) {
            return Err(CryptoError::InvalidNoiseHandshake);
        }

        let mut symmetric = SymmetricState::new();
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(&s.public().to_bytes());

        let (re, message) = message.split_at(32);
        let re = PublicKey::try_from(<[u8; 32]>::try_from(re).expect("slice length is 32"))?;
        symmetric.mix_hash(&re.to_bytes());
        symmetric.mix_key(s.diffie_hellman(&re).as_ref());

        let (rs, message) = message.split_at(48);
        let rs = PublicKey::try_from(
            <[u8; 32]>::try_from(symmetric.decrypt_and_hash(rs)?)
                .expect("48 ciphertext bytes decrypt to 32 public-key bytes"),
        )?;
        symmetric.mix_key(s.diffie_hellman(&rs).as_ref());
        let payload = symmetric.decrypt_and_hash(message)?;

        Ok((Self::Responding { symmetric, rs, re }, rs, payload))
    }

    pub(crate) fn write_response<R: CryptoRng>(
        self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, NoiseSession), CryptoError> {
        if payload.len() > u16::MAX as usize - 48 {
            return Err(CryptoError::InvalidNoiseHandshake);
        }

        let Self::Responding {
            mut symmetric,
            rs,
            re,
        } = self
        else {
            unreachable!();
        };

        let e = PrivateKey::generate(rng);
        let mut message = Vec::with_capacity(48 + payload.len());
        message.extend(e.public().to_bytes());
        symmetric.mix_hash(&message);
        symmetric.mix_key(e.diffie_hellman(&re).as_ref());
        symmetric.mix_key(e.diffie_hellman(&rs).as_ref());
        message.extend(symmetric.encrypt_and_hash(payload)?);

        let (recv, send) = symmetric.split();

        Ok((
            message,
            NoiseSession {
                send,
                send_epoch: 0,
                recv,
                recv_epoch: 0,
                previous_recv: None,
                window: Window::default(),
            },
        ))
    }

    pub(crate) fn read_response(
        self,
        message: &[u8],
    ) -> Result<(Vec<u8>, NoiseSession), CryptoError> {
        if !(48..=u16::MAX as usize).contains(&message.len()) {
            return Err(CryptoError::InvalidNoiseHandshake);
        }

        let Self::AwaitingResponse {
            mut symmetric,
            s,
            e,
        } = self
        else {
            unreachable!();
        };

        let (re, message) = message.split_at(32);
        let re = PublicKey::try_from(<[u8; 32]>::try_from(re).expect("slice length is 32"))?;
        symmetric.mix_hash(&re.to_bytes());
        symmetric.mix_key(e.diffie_hellman(&re).as_ref());
        symmetric.mix_key(s.diffie_hellman(&re).as_ref());
        let payload = symmetric.decrypt_and_hash(message)?;

        let (send, recv) = symmetric.split();

        Ok((
            payload,
            NoiseSession {
                send,
                send_epoch: 0,
                recv,
                recv_epoch: 0,
                previous_recv: None,
                window: Window::default(),
            },
        ))
    }
}
