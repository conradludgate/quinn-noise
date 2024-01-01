use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};

#[tokio::main]
async fn main() {
    let mut csprng = rand::rngs::OsRng {};
    let secret_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let public_key = secret_key.verifying_key();

    let (server_addr, endpoint) = server_endpoint(secret_key);

    tokio::spawn(async move {
        if let Err(e) = server(endpoint).await {
            eprintln!("server failed: {e:#}");
        }
    });
    if let Err(e) = client(server_addr, public_key).await {
        eprintln!("client failed: {e:#}");
    }
}

async fn server(endpoint: quinn::Endpoint) -> Result<()> {
    loop {
        let handshake = endpoint.accept().await.unwrap();
        let connection = handshake.await.context("handshake failed")?;

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
    remote_public_key: ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let (endpoint, connection) = connect_client(server_addr, remote_public_key).await?;
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
fn server_endpoint(keypair: ed25519_dalek::SigningKey) -> (SocketAddr, quinn::Endpoint) {
    let crypto = Arc::new(quinn_noise::NoiseConfig::from(
        quinn_noise::NoiseServerConfig {
            keypair,
            keylogger: None,
            psk: None,
            supported_protocols: vec![b"test".to_vec()],
        },
    ));

    let server_config = quinn::ServerConfig::with_crypto(crypto);
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = quinn::Endpoint::server(server_config, socket).unwrap();

    let server_addr = endpoint.local_addr().unwrap();
    (server_addr, endpoint)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    remote_public_key: ed25519_dalek::VerifyingKey,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let mut csprng = rand::rngs::OsRng {};
    let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
    let crypto = quinn_noise::NoiseConfig::from(quinn_noise::NoiseClientConfig {
        remote_public_key,
        requested_protocols: vec![b"test".to_vec()],
        keypair,
        psk: None,
        keylogger: None,
    });

    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = quinn::Endpoint::client(socket).unwrap();

    let connection = endpoint
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;

    Ok((endpoint, connection))
}
