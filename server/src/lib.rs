use bytecodec::{DecodeExt, EncodeExt};
use bytes::Bytes;
use common::{PacketType, PacketTypeDecoder, PacketTypeEncoder, Peer, NAT_TYPE_UNKNOW};
use log::{debug, info, warn};
use std::{collections::HashMap, net::SocketAddr};

use tokio::net::UdpSocket;

pub struct Server {
    peers: HashMap<String, Peer>,
    socket: UdpSocket,
    ping_count: usize,
}

impl Server {
    pub async fn new(listen: SocketAddr) -> Self {
        Self {
            peers: Default::default(),
            socket: UdpSocket::bind(listen).await.unwrap(),
            ping_count: 0,
        }
    }

    pub async fn run(&mut self) {
        info!("server listen socket: {:?}", self.socket.local_addr());

        let mut buf = [0u8; 1024];
        while let Ok((size, addr)) = self.socket.recv_from(&mut buf).await {
            let buf = &buf[..size];
            info!("received: {:?}", buf);
            let packet = {
                let bytes = Bytes::copy_from_slice(&buf);
                let mut packet_type_decoder = PacketTypeDecoder::default();
                let packet_type = packet_type_decoder.decode_from_bytes(&bytes).unwrap();
                packet_type
            };

            self.handle_packet(packet, addr).await;
        }
    }

    async fn handle_packet(&mut self, packet: PacketType, recv_addr: SocketAddr) {
        match packet {
            PacketType::Register(peer) => self.handle_register_packet(peer),
            PacketType::Query(email) => {
                self.handle_query_peer(email, recv_addr).await;
            }
            PacketType::Ping => {
                debug!("ping");
                self.ping_count += 1;
            }
            PacketType::Peer(_) => { /* ignore */ }
        }
    }

    async fn handle_query_peer(&mut self, email: String, recv_addr: SocketAddr) {
        let peer = if let Some(peer) = self.peers.get(&email) {
            debug!("founnd peer: {:?}", peer);
            peer.clone()
        } else {
            warn!("cannot found public address of email: {}", email);
            Peer::new(String::new(), NAT_TYPE_UNKNOW, "0.0.0.0:0".parse().unwrap())
        };

        let mut packet_type_encoder = PacketTypeEncoder::default();
        let bytes = packet_type_encoder
            .encode_into_bytes(PacketType::Peer(peer.clone()))
            .unwrap();

        debug!("sent back the peer");
        self.socket.send_to(&bytes, recv_addr).await.unwrap();
    }

    fn handle_register_packet(&mut self, peer: Peer) {
        debug!("register peer: {:?}", peer);
        let email = peer.get_email();
        self.peers.insert(email, peer);
    }
}
