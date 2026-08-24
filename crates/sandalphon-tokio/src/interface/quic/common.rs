use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{
    ClientConfig, Connection, Endpoint, Incoming, RecvStream, SendStream, ServerConfig,
    TransportConfig, crypto::rustls::QuicClientConfig,
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sandalphon_core::link::LinkFrame;
use tokio::{sync::mpsc, task::JoinHandle};

use super::{QuicInterfaceError, QuicLinkConfig};
use crate::{RuntimeHandle, runtime::AttachedLink};

const FRAME_PREFIX_LEN: usize = size_of::<u32>();
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

pub(super) struct QuicInterfaceState {
    endpoint: Endpoint,
    task: JoinHandle<()>,
}

impl QuicInterfaceState {
    pub(super) fn new(endpoint: Endpoint, task: JoinHandle<()>) -> Self {
        Self { endpoint, task }
    }

    pub(super) fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.endpoint.local_addr()
    }
}

impl Drop for QuicInterfaceState {
    fn drop(&mut self) {
        self.endpoint.close(0_u8.into(), b"interface closed");
        self.task.abort();
    }
}

pub(super) fn reconnect_delay(base: Duration) -> Duration {
    let maximum_nanos = u64::try_from(base.as_nanos()).unwrap_or(u64::MAX);
    let minimum_nanos = (maximum_nanos / 2).max(1);
    let spread = maximum_nanos.saturating_sub(minimum_nanos);
    let random = getrandom::u64().unwrap_or_default();
    Duration::from_nanos(minimum_nanos.saturating_add(random % spread.saturating_add(1)))
}

pub(super) fn increase_reconnect_delay(current: Duration, maximum: Duration) -> Duration {
    current.saturating_mul(2).min(maximum)
}

pub(super) async fn run_outgoing_connection(
    endpoint: &Endpoint,
    address: SocketAddr,
    runtime: RuntimeHandle,
    config: QuicLinkConfig,
) -> Result<(), QuicInterfaceError> {
    let connecting = endpoint.connect(address, "sandalphon")?;
    let setup = async {
        let connection = connecting.await?;
        let (send, receive) = connection.open_bi().await?;
        Ok::<_, quinn::ConnectionError>((connection, send, receive))
    };
    let (connection, send, receive) = tokio::time::timeout(config.setup_timeout, setup)
        .await
        .map_err(|_| QuicInterfaceError::SetupTimeout)??;
    run_connection(connection, send, receive, runtime, config)
        .await
        .map_err(QuicInterfaceError::Link)
}

pub(super) async fn run_incoming_connection(
    incoming: Incoming,
    runtime: RuntimeHandle,
    config: QuicLinkConfig,
) -> Result<(), QuicInterfaceError> {
    let setup = async {
        let connection = incoming.await?;
        let (send, receive) = connection.accept_bi().await?;
        Ok::<_, quinn::ConnectionError>((connection, send, receive))
    };
    let (connection, send, receive) = tokio::time::timeout(config.setup_timeout, setup)
        .await
        .map_err(|_| QuicInterfaceError::SetupTimeout)??;
    run_connection(connection, send, receive, runtime, config)
        .await
        .map_err(QuicInterfaceError::Link)
}

pub(super) async fn run_connection(
    connection: Connection,
    mut send: SendStream,
    mut receive: RecvStream,
    runtime: RuntimeHandle,
    config: QuicLinkConfig,
) -> Result<(), String> {
    let remote = connection.remote_address();
    let (outgoing, frames) = mpsc::channel(config.outgoing_capacity);
    let (completion, completion_signal) = tokio::sync::oneshot::channel();
    let link = match runtime
        .attach(config.runtime_config(), outgoing, completion)
        .await
    {
        Ok(link) => link,
        Err(error) => {
            return Err(format!("{remote}: {error}"));
        }
    };
    let link_id = link.id();
    let lifetime = tokio::time::sleep(config.edge_lifetime);
    tokio::pin!(lifetime);
    let reader = receive_frames(&mut receive, link.clone(), usize::from(config.mtu));
    tokio::pin!(reader);
    let writer = send_frames(&mut send, frames, usize::from(config.mtu));
    tokio::pin!(writer);
    tokio::pin!(completion_signal);

    let result = tokio::select! {
        () = &mut lifetime => Ok(()),
        result = &mut reader => result,
        result = &mut writer => result,
        outcome = &mut completion_signal => outcome.unwrap_or(Ok(())),
        error = connection.closed() => {
            match error {
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed => Ok(()),
                error => Err(error.to_string()),
            }
        }
    };

    connection.close(0_u8.into(), b"link closed");
    link.detach().await;
    result.map_err(|message| format!("{remote} ({link_id:?}): {message}"))
}

async fn receive_frames(
    receive: &mut RecvStream,
    link: AttachedLink,
    maximum: usize,
) -> Result<(), String> {
    loop {
        let Some(frame) = read_frame(receive, maximum).await? else {
            return Ok(());
        };
        link.received(frame)
            .await
            .map_err(|error| error.to_string())?;
    }
}

async fn send_frames(
    send: &mut SendStream,
    mut frames: mpsc::Receiver<LinkFrame>,
    maximum: usize,
) -> Result<(), String> {
    while let Some(frame) = frames.recv().await {
        write_frame(send, frame, maximum).await?;
    }
    Ok(())
}

async fn read_frame(receive: &mut RecvStream, maximum: usize) -> Result<Option<LinkFrame>, String> {
    let mut prefix = [0; FRAME_PREFIX_LEN];
    match receive.read_exact(&mut prefix).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(error) => return Err(format!("could not read frame length: {error}")),
    }

    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| "frame length does not fit in usize".to_owned())?;
    if length == 0 || length > maximum {
        return Err(format!(
            "invalid frame length {length}; maximum is {maximum}"
        ));
    }

    let mut bytes = vec![0; length];
    receive
        .read_exact(&mut bytes)
        .await
        .map_err(|error| format!("could not read frame: {error}"))?;
    LinkFrame::from_bytes(&bytes)
        .map(Some)
        .ok_or_else(|| "received an invalid Sandalphon frame".to_owned())
}

async fn write_frame(
    send: &mut SendStream,
    frame: LinkFrame,
    maximum: usize,
) -> Result<(), String> {
    let bytes = frame.to_bytes();
    if bytes.len() > maximum {
        return Err(format!(
            "encoded frame length {} exceeds maximum {maximum}",
            bytes.len()
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "encoded frame is too large".to_owned())?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|error| format!("could not write frame length: {error}"))?;
    send.write_all(&bytes)
        .await
        .map_err(|error| format!("could not write frame: {error}"))
}

pub(super) fn server_config() -> Result<ServerConfig, QuicInterfaceError> {
    let certificate = rcgen::generate_simple_self_signed(vec!["sandalphon".to_owned()])?;
    let certificate_der = CertificateDer::from(certificate.cert);
    let private_key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let mut config = ServerConfig::with_single_cert(vec![certificate_der], private_key.into())?;
    let transport = Arc::get_mut(&mut config.transport)
        .expect("new server configuration owns its transport configuration");
    transport.max_concurrent_bidi_streams(1_u8.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    Ok(config)
}

pub(super) fn client_config() -> Result<ClientConfig, QuicInterfaceError> {
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SandalphonCertificateVerifier::new())
        .with_no_client_auth();
    let quic = QuicClientConfig::try_from(tls).map_err(|_| {
        QuicInterfaceError::InvalidConfig("TLS provider has no QUIC-compatible cipher suite")
    })?;
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    let mut config = ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[derive(Debug)]
struct SandalphonCertificateVerifier(Arc<CryptoProvider>);

impl SandalphonCertificateVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SandalphonCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // We aren't verifying TLS certs
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signed,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signed,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
