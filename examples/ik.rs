use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use noise_protocol::DH;
use noise_protocol_quinn::{
    noise_protocol::{patterns::noise_ik, HandshakeStateBuilder},
    HandshakeData, NoiseConfig,
};
use noise_rust_crypto::{sensitive::Sensitive, Blake2b, ChaCha20Poly1305, X25519};
use quinn::TokioRuntime;
use rand_core::OsRng;
use zeroize::Zeroizing;

/// You must use a different version. 0x00000000 - 0x0000ffff is reserved.
/// See <https://github.com/quicwg/base-drafts/wiki/QUIC-Versions>
const QUIC_VERSION: u32 = 0xf00dcafe;

#[tokio::main]
async fn main() {
    let server_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let server_public_key = x25519_dalek::PublicKey::from(&server_secret_key);

    let client_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let client_public_key = x25519_dalek::PublicKey::from(&client_secret_key);

    let (server_addr, endpoint) = server_endpoint(server_secret_key);

    tokio::spawn(async move {
        if let Err(e) = server(endpoint, client_public_key).await {
            eprintln!("server failed: {e:#}");
        }
    });
    if let Err(e) = client(server_addr, client_secret_key, server_public_key).await {
        eprintln!("client failed: {e:#}");
    }
}

async fn server(
    endpoint: quinn::Endpoint,
    remote_public_key: x25519_dalek::PublicKey,
) -> Result<()> {
    loop {
        let handshake = endpoint.accept().await.unwrap();
        let connection = handshake.await.context("handshake failed")?;

        let peer = connection
            .peer_identity()
            .unwrap()
            .downcast::<<X25519 as DH>::Pubkey>()
            .unwrap();
        assert_eq!(*peer, remote_public_key.to_bytes());

        tokio::spawn(async move {
            loop {
                let (mut send_stream, mut recv_stream) = match connection.accept_bi().await {
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => {
                        eprintln!("accepting stream failed: {e:?}");
                        break;
                    }
                    Ok(stream) => stream,
                };

                let data = recv_stream.read_to_end(1024).await.unwrap();
                assert_eq!(&data[..], &[42; 1024]);

                send_stream.write_all(&data).await.unwrap();
                send_stream.finish().await.unwrap();
            }
        });
    }
}

async fn client(
    server_addr: SocketAddr,
    keypair: x25519_dalek::StaticSecret,
    remote_public_key: x25519_dalek::PublicKey,
) -> Result<()> {
    let (endpoint, connection) = connect_client(server_addr, keypair, remote_public_key).await?;
    let connection = Arc::new(connection);

    let (mut send_stream, mut recv_stream) = connection
        .open_bi()
        .await
        .context("failed to open stream")?;

    let download = tokio::spawn(async move { recv_stream.read_to_end(1024).await });

    let data = [42; 1024];
    send_stream.write_all(&data).await?;
    send_stream.finish().await?;

    let downloaded = download.await??;

    ensure!(&data[..] == &downloaded[..]);

    connection.close(0u32.into(), b"Test done");
    endpoint.wait_idle().await;

    Ok(())
}

fn new_endpoint(server_config: Option<quinn::ServerConfig>) -> std::io::Result<quinn::Endpoint> {
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(vec![QUIC_VERSION]);

    let runtime = Arc::new(TokioRuntime);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let socket = UdpSocket::bind(addr).unwrap();

    quinn::Endpoint::new(endpoint_config, server_config, socket, runtime)
}

/// Creates a server endpoint
fn server_endpoint(keypair: x25519_dalek::StaticSecret) -> (SocketAddr, quinn::Endpoint) {
    let mut handshake = HandshakeStateBuilder::<X25519>::new();
    handshake
        .set_prologue(&[])
        .set_pattern(noise_ik())
        .set_is_initiator(false)
        .set_s(Sensitive::from(Zeroizing::new(keypair.to_bytes())));
    let handshake = handshake.build_handshake_state::<ChaCha20Poly1305, Blake2b>();
    let protocols = vec![b"test2".to_vec(), b"test1".to_vec()];
    let crypto = NoiseConfig::new(handshake, protocols);

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = new_endpoint(Some(server_config)).unwrap();

    let server_addr = endpoint.local_addr().unwrap();
    (server_addr, endpoint)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    keypair: x25519_dalek::StaticSecret,
    remote_public_key: x25519_dalek::PublicKey,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let mut handshake = HandshakeStateBuilder::<X25519>::new();
    handshake
        .set_prologue(&[])
        .set_pattern(noise_ik())
        .set_is_initiator(true)
        .set_s(Sensitive::from(Zeroizing::new(keypair.to_bytes())))
        .set_rs(remote_public_key.to_bytes());
    let handshake = handshake.build_handshake_state::<ChaCha20Poly1305, Blake2b>();
    let protocols = vec![b"test3".to_vec(), b"test1".to_vec(), b"test2".to_vec()];
    let crypto = NoiseConfig::new(handshake, protocols);

    let endpoint = new_endpoint(None).unwrap();

    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.version(QUIC_VERSION);

    let connection = endpoint
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;

    let peer = connection
        .peer_identity()
        .unwrap()
        .downcast::<<X25519 as DH>::Pubkey>()
        .unwrap();
    assert_eq!(*peer, remote_public_key.to_bytes());

    let data = connection
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap();
    assert_eq!(data.alpn, b"test1");

    Ok((endpoint, connection))
}
