use client;
use log::info;
use std::{
    env::args,
    io::{stdin, stdout, Write},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();
    env_logger::init();

    let server_addr = args().nth(1).unwrap();

    let email = {
        print!("enter your email: ");
        stdout().flush().unwrap();
        let mut email = String::new();
        let stdin = stdin();
        stdin.read_line(&mut email).unwrap();
        email
    };

    let mut client = client::Client::new(email, server_addr.parse().unwrap()).await;

    client.run().await
}
