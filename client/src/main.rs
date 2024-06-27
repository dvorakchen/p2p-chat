use client;
use client::client::instructions::Instruction;

use log::{info, warn};
use std::{
    env::args,
    io::{stdin, stdout, Write},
};
use tokio::io::{AsyncBufReadExt, BufReader};

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
        email.trim().to_string()
    };

    let mut client = client::Client::new(email, server_addr.parse().unwrap()).await;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();

        if line.starts_with(':') {
            match &line[1..] {
                "q" => client.instruct(Instruction::Quit).await,
                v => warn!("unknown instruction: {}", v),
            }
        } else {
            client.run().await.unwrap();
        }
    }

    Ok(())
}
