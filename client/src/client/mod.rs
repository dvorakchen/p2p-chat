pub mod instructions;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Ok;
use bytecodec::EncodeExt;
use bytes::Bytes;
use common::{PacketType, PacketTypeEncoder, Peer};
use instructions::Instruction;
use log::{info, trace};
use nat_detect::{nat_detect, NatType};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{constant::DEFAULT_STUN_ADDRESS, errors::Errors};

pub struct Client {
    email: String,
    socket: Arc<Mutex<UdpSocket>>,
    nat_type: common::NatType,
    server_addr: SocketAddr,
    pub_addr: SocketAddr,
}

impl Client {
    pub async fn new(email: impl AsRef<str>, server_addr: SocketAddr) -> Self {
        Self {
            email: email.as_ref().to_string(),
            socket: Arc::new(Mutex::new(UdpSocket::bind("0.0.0.0:0").await.unwrap())),
            nat_type: common::NAT_TYPE_UNKNOW,
            server_addr,
            pub_addr: "0.0.0.0:0".parse().unwrap(),
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("detecting NAT type...");
        let (pub_addr, nat_type) = self.detect_nat_type().await?;
        info!(
            "NAT detected, public address: {}, NAT type: {:?}",
            pub_addr, nat_type
        );

        self.register_2_server().await?;

        Ok(())
    }

    async fn detect_nat_type(&mut self) -> anyhow::Result<(SocketAddr, NatType)> {
        let (stun_ser, pub_addr, nat_type) = {
            let socket = self.socket.lock().await;
            nat_detect(socket.local_addr()?, &DEFAULT_STUN_ADDRESS)
                .await
                .map_err(|_| Errors::NatDetectFailed)?
        };

        trace!(
            "NAT detected successful: STUN: {}, public address: {}, NAT type: {:?}",
            stun_ser,
            pub_addr,
            nat_type
        );

        self.nat_type = nat_type.into();
        self.pub_addr = pub_addr;
        Ok((pub_addr, nat_type))
    }

    /// register current peer information to server and keep ping
    pub async fn register_2_server(&mut self) -> anyhow::Result<()> {
        let packet =
            PacketType::Register(Peer::new(self.email.clone(), self.nat_type, self.pub_addr));

        info!("packet: {:?}", packet);
        let mut packet_type_encoder = PacketTypeEncoder::default();
        let bytes = packet_type_encoder.encode_into_bytes(packet)?;
        // let bytes = packet.to_message_bytes();
        info!("packet bytes: {:?}", bytes);

        {
            let socket = self.socket.lock().await;
            socket.send_to(&bytes, self.server_addr).await?;
        }

        let ping_socket = Arc::clone(&self.socket);
        let server_addr = self.server_addr;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;
                {
                    let socket = ping_socket.lock().await;
                    socket.send_to(&[0u8; 0], server_addr).await.unwrap();
                }
            }
        });

        Ok(())
    }

    pub async fn instruct(&mut self, instruction: Instruction) {
        match instruction {
            Instruction::Quit => { /* close client */ }
            Instruction::TalkTo(email) => {
                self.ask_peer(email).await.unwrap();
            }
        }
    }

    pub async fn ask_peer(&mut self, peer_email: String) -> anyhow::Result<Option<Peer>> {
        let mut packet_type_encoder = PacketTypeEncoder::default();

        let packet_type = PacketType::Query(peer_email);
        let bytes = packet_type_encoder.encode_into_bytes(packet_type)?;

        let recv_bytes = {
            let socket = self.socket.lock().await;
            socket.send_to(&bytes, self.server_addr).await?;

            let mut buf = [0u8; 1024];
            let (size, _) = socket.recv_from(&mut buf).await?;
            Bytes::copy_from_slice(&buf[..size])
        };

        if recv_bytes.len() == 0 {
            Ok(None)
        } else {
            Ok(None)
        }
    }
}
