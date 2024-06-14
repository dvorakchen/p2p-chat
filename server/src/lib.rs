use bytes::Bytes;
use common::{PacketType, Peer};
use log::{info, warn};

use std::{collections::HashMap, net::SocketAddr};

use tokio::net::UdpSocket;

pub struct Server {
    peers: HashMap<String, Peer>,
    socket: UdpSocket,
}

impl Server {
    pub async fn new(listen: SocketAddr) -> Self {
        Self {
            peers: Default::default(),
            socket: UdpSocket::bind(listen).await.unwrap(),
        }
    }

    pub async fn run(&mut self) {
        info!("server listen socket: {:?}", self.socket.local_addr());

        let mut buf = [0u8; 1024];
        while let Ok((size, addr)) = self.socket.recv_from(&mut buf).await {
            let packet = {
                let bytes = Bytes::copy_from_slice(&buf[..size]);
                PacketType::try_from(bytes).unwrap()
            };

            self.handle_packet(packet, addr).await;
        }
    }

    async fn handle_packet(&mut self, packet: PacketType, recv_addr: SocketAddr) {
        match packet {
            PacketType::Register(peer) => self.handle_register_packet(peer),
            PacketType::QueryAddr(email) => {
                if let Some(peer) = self.peers.get(&email) {
                    let bytes = peer.to_message_bytes();
                    self.socket.send_to(&bytes, recv_addr).await.unwrap();
                } else {
                    warn!("cannot found public address of email: {}", email);
                }
            }
        }
    }

    fn handle_register_packet(&mut self, peer: Peer) {
        let email = peer.get_email();
        self.peers.insert(email, peer);
    }
}
