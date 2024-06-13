mod peers;

use bytes::Bytes;
use log::warn;
use peers::{PacketType, Peer};

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
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        let mut buf = [0u8; 1024];
        while let Ok((size, addr)) = socket.recv_from(&mut buf).await {
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
                if let Some(pub_addr) = self.handle_query_packet(&email) {

                    let bytes: Bytes = pub_addr.get_pub_addr().to_string().into();
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

    fn handle_query_packet(&mut self, email: &String) -> Option<&Peer> {
        self.peers.get(email)
    }
}
