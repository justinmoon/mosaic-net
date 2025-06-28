use mosaic_core::*;
use mosaic_net::*;
use std::io::Write;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_secret_key = {
        let mut csprng = rand::rngs::OsRng;
        SecretKey::generate(&mut csprng)
    };
    println!("Client public key: {}", client_secret_key.public());

    let server_public_key =
        PublicKey::from_printable("mopub03ctpjer5jfkd49rxe4767hk9ij6f8sdtryjnnru1bpwxhcykk54o")?;

    let server_socket: SocketAddr = "127.0.0.1:8081".parse()?;

    let client_config =
        ClientConfig::new(server_public_key, server_socket, Some(client_secret_key))?;

    let client = client_config.client(None).await?;

    let (mut send, mut recv) = client.inner().open_bi().await?;

    // Write a "ping"
    send.write_all(b"ping").await?;
    send.finish()?;

    // Read full response from the server
    let resp = recv.read_to_end(1024 * 1024).await?;
    std::io::stdout().write_all(&resp).unwrap();
    std::io::stdout().flush().unwrap();
    println!("");

    client.close(0, b"client is done").await;

    Ok(())
}
