use client;
use client::client::instructions::Instruction;

use log::{error, warn};
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

    client.run().await.unwrap();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();

        if line.starts_with(':') {
            let raw_instructions: Vec<_> = line[1..].split(|v: char| v.is_whitespace()).collect();

            match raw_instructions[0] {
                // instruction :q
                "q" => {
                    client.instruct(Instruction::Quit).await;
                    break;
                }
                // instruction :t <email>
                "t" => {
                    if raw_instructions.len() < 2 {
                        error!("wrong instruction: {}", line);
                        continue;
                    }
                    let email = raw_instructions[1];
                    client
                        .instruct(Instruction::TalkTo(email.to_string()))
                        .await;
                }
                v => warn!("unknown instruction: {}", v),
            }
        }
    }

    Ok(())
}
