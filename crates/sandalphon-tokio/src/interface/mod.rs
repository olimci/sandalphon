use std::future::Future;

use crate::RuntimeHandle;

#[cfg(feature = "interface-memory")]
pub mod memory;
#[cfg(feature = "interface-quic")]
pub mod quic;

pub trait Interface: Sized {
    type Config;
    type Error;

    fn new(
        runtime: RuntimeHandle,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}
