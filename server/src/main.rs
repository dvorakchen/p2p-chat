use anyhow::Ok;
use server::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();
    env_logger::init();

    let server = Server::new("0.0.0.0:8743".parse().unwrap()).await;

    Ok(())
}
