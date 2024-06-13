use std::net::SocketAddr;

use anyhow::Ok;
use log::trace;
use nat_detect::{nat_detect, NatType};
use tokio::net::UdpSocket;

use crate::{constant::DEFAULT_STUN_ADDRESS, errors::Errors};

pub struct Client {
    email: String,
    socket: UdpSocket,
    nat_type: NatType,
}

impl Client {
    pub async fn new(email: impl AsRef<str>) -> Self {
        Self {
            email: email.as_ref().to_string(),
            socket: UdpSocket::bind("0.0.0.0:0").await.unwrap(),
            nat_type: NatType::Unknown,
        }
    }

    pub async fn detect_nat_type(&mut self) -> anyhow::Result<(SocketAddr, NatType)> {
        let (stun_ser, pub_addr, nat_type) =
            nat_detect(self.socket.local_addr()?, &DEFAULT_STUN_ADDRESS)
                .await
                .map_err(|_| Errors::NatDetectFailed)?;
        trace!(
            "NAT detected successful: STUN: {}, public address: {}, NAT type: {:?}",
            stun_ser,
            pub_addr,
            nat_type
        );

        self.nat_type = nat_type;
        Ok((pub_addr, nat_type))
    }
}
