use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use quinn_noise::{HandshakeData, PublicKeyVerifier};
use rand_core::OsRng;
use x25519_dalek::PublicKey;

#[tokio::main]
async fn main() {
    let server_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let server_public_key = x25519_dalek::PublicKey::from(&server_secret_key);

    let client_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let client_public_key = x25519_dalek::PublicKey::from(&client_secret_key);

    let (server_addr, endpoint) = server_endpoint(server_secret_key, client_public_key);

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
            .downcast::<PublicKey>()
            .unwrap();
        assert_eq!(*peer, remote_public_key);

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

/// Creates a server endpoint
fn server_endpoint(
    keypair: x25519_dalek::StaticSecret,
    remote_public_key: x25519_dalek::PublicKey,
) -> (SocketAddr, quinn::Endpoint) {
    let crypto = Arc::new(quinn_noise::NoiseServerConfig {
        keypair,
        supported_protocols: vec![b"test1".to_vec(), b"test2".to_vec()],
        remote_public_key_verifier: Arc::new(Verifier([remote_public_key].into_iter().collect())),
    });

    let server_config = quinn::ServerConfig::with_crypto(crypto);
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = quinn::Endpoint::server(server_config, socket).unwrap();

    let server_addr = endpoint.local_addr().unwrap();
    (server_addr, endpoint)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    keypair: x25519_dalek::StaticSecret,
    remote_public_key: x25519_dalek::PublicKey,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let crypto = quinn_noise::NoiseClientConfig {
        remote_public_key,
        requested_protocols: vec![b"test3".to_vec(), b"test1".to_vec(), b"test2".to_vec()],
        keypair,
    };

    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = quinn::Endpoint::client(socket).unwrap();

    let connection = endpoint
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;

    let peer = connection
        .peer_identity()
        .unwrap()
        .downcast::<PublicKey>()
        .unwrap();
    assert_eq!(*peer, remote_public_key);

    let data = connection
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap();
    assert_eq!(data.alpn, b"test1");

    Ok((endpoint, connection))
}

pub struct Verifier(HashSet<PublicKey>);
impl PublicKeyVerifier for Verifier {
    fn verify(&self, key: &x25519_dalek::PublicKey) -> bool {
        self.0.contains(key)
    }
}
