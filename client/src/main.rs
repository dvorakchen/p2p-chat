use client;
use log::info;
use std::io::{stdin, stdout, Write};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();
    env_logger::init();

    let email = {
        print!("enter your email: ");
        stdout().flush().unwrap();
        let mut email = String::new();
        let stdin = stdin();
        stdin.read_line(&mut email).unwrap();
        email
    };

    let mut client = client::Client::new(email).await;

    info!("detecting NAT type...");
    let (pub_addr, nat_type) = client.detect_nat_type().await?;
    info!(
        "NAT detected, public address: {}, NAT type: {:?}",
        pub_addr, nat_type
    );

    Ok(())
}
