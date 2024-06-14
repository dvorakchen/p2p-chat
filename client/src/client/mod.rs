use std::{net::SocketAddr, sync::Arc};

use anyhow::Ok;
use log::{info, trace};
use nat_detect::{nat_detect, NatType};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{constant::DEFAULT_STUN_ADDRESS, errors::Errors};

pub struct Client {
    email: String,
    socket: Arc<Mutex<UdpSocket>>,
    nat_type: NatType,
    server_addr: SocketAddr,
}

impl Client {
    pub async fn new(email: impl AsRef<str>, server_addr: SocketAddr) -> Self {
        Self {
            email: email.as_ref().to_string(),
            socket: Arc::new(Mutex::new(UdpSocket::bind("0.0.0.0:0").await.unwrap())),
            nat_type: NatType::Unknown,
            server_addr: server_addr,
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("detecting NAT type...");
        let (pub_addr, nat_type) = self.detect_nat_type().await?;
        info!(
            "NAT detected, public address: {}, NAT type: {:?}",
            pub_addr, nat_type
        );

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

        self.nat_type = nat_type;
        Ok((pub_addr, nat_type))
    }

    /// register current peer information to server and keep ping
    pub async fn register_2_server(&mut self) {

        
    }
}
