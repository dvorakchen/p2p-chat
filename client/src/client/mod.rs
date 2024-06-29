pub mod instructions;
mod socket;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytecodec::{DecodeExt, EncodeExt};
use bytes::Bytes;
use common::{PacketType, PacketTypeDecoder, PacketTypeEncoder, PacketTypeError, Peer};
use instructions::Instruction;
use log::{debug, error, info, trace, warn};
use nat_detect::{nat_detect, NatType};
use socket::{ReadUdpSocket, WriteUdpSocket};
use tokio::net::UdpSocket;

use crate::{constant::DEFAULT_STUN_ADDRESS, errors::Errors};

pub struct Client {
    email: String,
    read_socket: Arc<ReadUdpSocket>,
    write_socket: Arc<WriteUdpSocket>,
    nat_type: common::NatType,
    server_addr: SocketAddr,
    pub_addr: SocketAddr,
    talk_to: Option<Peer>,
}

impl Client {
    pub async fn new(email: impl AsRef<str>, server_addr: SocketAddr) -> Self {
        let (read_socket, write_socket) = {
            let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            socket::udpsocket_split(socket)
        };

        Self {
            email: email.as_ref().to_string(),
            read_socket: Arc::new(read_socket),
            write_socket: Arc::new(write_socket),
            nat_type: common::NAT_TYPE_UNKNOW,
            server_addr,
            pub_addr: "0.0.0.0:0".parse().unwrap(),
            talk_to: None,
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
            let local_addr = self.read_socket.local_addr()?;
            nat_detect(local_addr, &DEFAULT_STUN_ADDRESS)
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
            // let socket = self.socket.lock().await;
            self.write_socket.send_to(&bytes, self.server_addr).await?;
        }

        //  send Ping in cycles
        let ping_socket = Arc::clone(&self.write_socket);
        let server_addr = self.server_addr;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            let mut packet_type_encoder = PacketTypeEncoder::default();
            let bytes = packet_type_encoder
                .encode_into_bytes(PacketType::Ping)
                .unwrap();

            loop {
                interval.tick().await;
                {
                    ping_socket.send_to(&bytes, server_addr).await.unwrap();
                }
            }
        });

        Ok(())
    }

    pub async fn instruct(&mut self, instruction: Instruction) {
        match instruction {
            Instruction::Quit => { /* close client */ }
            Instruction::TalkTo(email) => {
                if let Err(e) = self.handle_talk_to(email.clone()).await {
                    error!("talk to {} error {}", email, e);
                } else {
                    info!("peer: <{}> availabe", email);
                    listen_incoming_message(Arc::clone(&self.read_socket));
                }
            }
            Instruction::List => {
                self.handle_list().await;
            }
            Instruction::SendMessage(msg) => {
                if self.talk_to.is_none() {
                    warn!("you have not specified a peer");
                    return;
                }
                self.handle_send_msg(msg).await;
            }
        }
    }

    async fn handle_send_msg(&mut self, msg: String) {
        if self.talk_to.is_none() {
            return;
        }

        let peer = self.talk_to.as_ref().unwrap();
        let peer_addr = peer.get_pub_addr();

        debug!("send message: <{}> to {}", msg, peer_addr);

        let bytes = {
            let mut encoder = PacketTypeEncoder::default();
            let packet = PacketType::Message(msg);
            encoder.encode_into_bytes(packet).unwrap()
        };

        self.write_socket.send_to(&bytes, peer_addr).await.unwrap();
        debug!("sent");
    }

    async fn handle_list(&mut self) {}

    async fn handle_talk_to(&mut self, email: String) -> anyhow::Result<()> {
        let peer = self.ask_peer(email.clone()).await?;
        if peer.is_none() {
            warn!("asked email: {} has not peer", email);
            return Err(PacketTypeError::HasNotPeer.into());
        }

        let peer = peer.unwrap();
        info!("asked email: {} peer: {:?}", email, peer);

        self.talk_to = Some(peer);

        Ok(())
    }

    async fn ask_peer(&mut self, peer_email: String) -> anyhow::Result<Option<Peer>> {
        let mut packet_type_encoder = PacketTypeEncoder::default();

        let packet_type = PacketType::Query(peer_email);
        let bytes = packet_type_encoder.encode_into_bytes(packet_type)?;

        let recv_bytes = {
            self.write_socket.send_to(&bytes, self.server_addr).await?;

            let mut buf = [0u8; 1024];
            let (size, _) = self.read_socket.recv_from(&mut buf).await?;
            Bytes::copy_from_slice(&buf[..size])
        };

        let mut decoder = PacketTypeDecoder::default();
        let packet_type = decoder.decode_from_bytes(&recv_bytes)?;

        if let PacketType::Peer(peer) = packet_type {
            if !peer.get_email().is_empty() {
                return Ok(Some(peer));
            }
        }
        Ok(None)
    }
}
fn listen_incoming_message(socket: Arc<ReadUdpSocket>) {
    tokio::spawn(async move {
        info!("listen incoming message");
        let mut buf = [0u8; 1024];
        while let Ok((size, addr)) = socket.recv_from(&mut buf).await {
            if size == 0 {
                continue;
            }

            info!("received from: {:?}", addr);
            println!("received: {}", String::from_utf8(buf.to_vec()).unwrap());
        }
    });
}
