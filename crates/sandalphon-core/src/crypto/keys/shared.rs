use k256::ecdh::SharedSecret as EcdhSharedSecret;

pub(crate) struct SharedSecret(pub(super) EcdhSharedSecret);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.raw_secret_bytes().as_ref()
    }
}
