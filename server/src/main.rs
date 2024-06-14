use std::env::args;

use anyhow::Ok;
use server::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();
    env_logger::init();

    let listen = args().nth(1).unwrap();

    let mut server = Server::new(listen.parse().unwrap()).await;
    server.run().await;

    Ok(())
}
