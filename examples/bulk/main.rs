use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use clap::Parser;
use rand_core::OsRng;
use tokio::sync::Semaphore;

mod compat;
mod stats;

use compat::{connect_client, drain_stream, rt, send_data_on_stream, server_endpoint, Opt};
use stats::{Stats, TransferResult};

fn main() {
    let opt = Opt::parse();

    let keypair = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public_key = x25519_dalek::PublicKey::from(&keypair);

    let runtime = rt();
    let (server_addr, endpoint) = server_endpoint(&runtime, keypair, &opt);

    let server_thread = std::thread::spawn(move || {
        if let Err(e) = runtime.block_on(server(endpoint, opt)) {
            eprintln!("server failed: {e:#}");
        }
    });

    let mut handles = Vec::new();
    for _ in 0..opt.clients {
        handles.push(std::thread::spawn(move || {
            let runtime = rt();
            match runtime.block_on(client(server_addr, public_key, opt)) {
                Ok(stats) => Ok(stats),
                Err(e) => {
                    eprintln!("client failed: {e:#}");
                    Err(e)
                }
            }
        }));
    }

    for (id, handle) in handles.into_iter().enumerate() {
        // We print all stats at the end of the test sequentially to avoid
        // them being garbled due to being printed concurrently
        if let Ok(stats) = handle.join().expect("client thread") {
            stats.print(id);
        }
    }

    server_thread.join().expect("server thread");
}

async fn server(endpoint: quinn::Endpoint, opt: Opt) -> Result<()> {
    let mut server_tasks = Vec::new();

    // Handle only the expected amount of clients
    for _ in 0..opt.clients {
        let handshake = endpoint.accept().await.unwrap();
        let connection = handshake.await.context("handshake failed")?;

        server_tasks.push(tokio::spawn(async move {
            loop {
                let (mut send_stream, mut recv_stream) = match connection.accept_bi().await {
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => {
                        eprintln!("accepting stream failed: {e:?}");
                        break;
                    }
                    Ok(stream) => stream,
                };

                tokio::spawn(
                    async move { drain_stream(&mut recv_stream, opt.read_unordered).await },
                );
                tokio::spawn(async move {
                    send_data_on_stream(&mut send_stream, opt.download_size).await
                });
            }

            if opt.stats {
                println!("\nServer connection stats:\n{:#?}", connection.stats());
            }
        }));
    }

    // Await all the tasks. We have to do this to prevent the runtime getting dropped
    // and all server tasks to be cancelled
    for handle in server_tasks {
        if let Err(e) = handle.await {
            eprintln!("Server task error: {e:?}");
        };
    }

    Ok(())
}

async fn client(
    server_addr: SocketAddr,
    remote_public_key: x25519_dalek::PublicKey,
    opt: Opt,
) -> Result<ClientStats> {
    let (endpoint, connection) = connect_client(server_addr, remote_public_key, opt).await?;

    let start = Instant::now();

    let connection = Arc::new(connection);

    let mut stats = ClientStats::default();
    let mut first_error = None;

    let sem = Arc::new(Semaphore::new(opt.max_streams));
    let results = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..opt.streams {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let results = results.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let result =
                handle_client_stream(connection, opt.upload_size, opt.read_unordered).await;
            results.lock().unwrap().push(result);
            drop(permit);
        });
    }

    // Wait for remaining streams to finish
    let _ = sem.acquire_many(opt.max_streams as u32).await.unwrap();

    for result in results.lock().unwrap().drain(..) {
        match result {
            Ok((upload_result, download_result)) => {
                stats.upload_stats.stream_finished(upload_result);
                stats.download_stats.stream_finished(download_result);
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    stats.upload_stats.total_duration = start.elapsed();
    stats.download_stats.total_duration = start.elapsed();

    // Explicit close of the connection, since handles can still be around due
    // to `Arc`ing them
    connection.close(0u32.into(), b"Benchmark done");

    endpoint.wait_idle().await;

    if opt.stats {
        println!("\nClient connection stats:\n{:#?}", connection.stats());
    }

    match first_error {
        None => Ok(stats),
        Some(e) => Err(e),
    }
}

async fn handle_client_stream(
    connection: Arc<quinn::Connection>,
    upload_size: u64,
    read_unordered: bool,
) -> Result<(TransferResult, TransferResult)> {
    let start = Instant::now();

    let (mut send_stream, mut recv_stream) = connection
        .open_bi()
        .await
        .context("failed to open stream")?;

    let upload = tokio::spawn(async move {
        send_data_on_stream(&mut send_stream, upload_size).await?;
        Result::<_, anyhow::Error>::Ok(TransferResult::new(start.elapsed(), upload_size))
    });
    let download = tokio::spawn(async move {
        let size = drain_stream(&mut recv_stream, read_unordered).await?;
        Result::<_, anyhow::Error>::Ok(TransferResult::new(start.elapsed(), size as u64))
    });

    let upload_result = upload.await??;
    let download_result = download.await??;

    Ok((upload_result, download_result))
}

#[derive(Default)]
struct ClientStats {
    upload_stats: Stats,
    download_stats: Stats,
}

impl ClientStats {
    pub fn print(&self, client_id: usize) {
        println!();
        println!("Client {client_id} stats:");

        if self.upload_stats.total_size != 0 {
            self.upload_stats.print("upload");
        }

        if self.download_stats.total_size != 0 {
            self.download_stats.print("download");
        }
    }
}
