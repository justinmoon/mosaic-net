use mosaic_core::*;
use mosaic_net::*;
use std::net::SocketAddr;
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_key =
        SecretKey::from_printable("mosec06ayb687prmw8abtuum9bps5hjmfz5ffyft3b4jeznn3htppf3kto")?;
    println!("SERVER PUBLIC KEY IS {}", secret_key.public());

    let server_socket: SocketAddr = "127.0.0.1:8081".parse()?;
    println!("SERVER ENDPOINT IS {}", server_socket);

    let server_config = ServerConfig::new(secret_key, server_socket)?;

    let server = Server::new(server_config)?;

    let mut interrupt_signal = signal(SignalKind::interrupt())?;
    let mut quit_signal = signal(SignalKind::quit())?;

    loop {
        tokio::select! {
            v = interrupt_signal.recv() => if v.is_some() {
                eprintln!("SIGINT");
                break;
            },
            v = quit_signal.recv() => if v.is_some() {
                eprintln!("SIGQUIT");
                break;
            },
            v = server.accept() => {
                let incoming_client: IncomingClient = v?;
                tokio::spawn(async move {
                    if let Err(e) = handle_client(incoming_client).await {
                        eprintln!("{e}");
                    }
                });
            },
        }
    }

    server.shut_down(0, b"Shutting down").await;
    eprintln!("Shut down.");

    Ok(())
}

async fn handle_client(incoming_client: IncomingClient) -> Result<(), Box<dyn std::error::Error>> {
    match incoming_client.accept(&AlwaysAllowedApprover).await {
        Ok(client_connection) => {
            println!("REMOTE IS {}", client_connection.remote_socket_addr());
            match client_connection.peer() {
                Some(peer) => println!("REMOTE PEER {}", peer),
                None => println!("ANONYMOUS"),
            }

            loop {
                let channel = client_connection.next_channel().await?;

                // Handle the channel in a parallel task so that we can handle
                // multiple channels in parallel
                tokio::spawn(async move {
                    if let Err(e) = handle_channel(channel).await {
                        eprintln!("{e}");
                    }
                });
            }
        }
        Err(e) => eprintln!("{e}"),
    }

    Ok(())
}

async fn handle_channel(mut channel: Channel) -> Result<(), Box<dyn std::error::Error>> {
    while let Some(message) = channel.recv().await? {
        match message.message_type() {
            MessageType::Submission => {
                let record = message.record().unwrap();
                let response = Message::new_submission_result(
                    SubmissionResultCode::RejectedRequiresAuthz,
                    record.id(),
                );
                channel.send(response).await?;
            }
            _ => {
                eprintln!("Unrecognized message: {message:?}");
                let response = Message::new_unrecognized();
                channel.send(response).await?;
            }
        }
    }

    Ok(())
}
