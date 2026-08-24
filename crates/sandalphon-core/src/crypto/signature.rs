use k256::schnorr::Signature as SchnorrSignature;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub(crate) SchnorrSignature);

impl Signature {
    pub const LEN: usize = 64;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0.to_bytes()
    }
}

impl TryFrom<[u8; Signature::LEN]> for Signature {
    type Error = k256::schnorr::Error;

    fn try_from(value: [u8; Signature::LEN]) -> Result<Self, Self::Error> {
        SchnorrSignature::try_from(value.as_slice()).map(Self)
    }
}
