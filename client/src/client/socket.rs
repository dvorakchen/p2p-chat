use std::{ops::Deref, sync::Arc};

use tokio::net::{ToSocketAddrs, UdpSocket};

pub struct ReadUdpSocket(Arc<UdpSocket>);
pub struct WriteUdpSocket(Arc<UdpSocket>);

pub fn udpsocket_split(udpsocket: UdpSocket) -> (ReadUdpSocket, WriteUdpSocket) {
    let read = Arc::new(udpsocket);
    let write = Arc::clone(&read);

    (ReadUdpSocket(read), WriteUdpSocket(write))
}

impl ReadUdpSocket {
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, std::net::SocketAddr), std::io::Error> {
        self.0.recv_from(buf).await
    }
}

impl WriteUdpSocket {
    pub async fn send_to(
        &self,
        buf: &[u8],
        target: impl ToSocketAddrs,
    ) -> Result<usize, std::io::Error> {
        self.0.send_to(buf, target).await
    }
}

impl Deref for ReadUdpSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        Arc::deref(&self.0)
    }
}

impl Deref for WriteUdpSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target {
        Arc::deref(&self.0)
    }
}
