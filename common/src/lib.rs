use bytes::Bytes;
use nat_detect::NatType;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug)]
pub struct Peer {
    email: String,
    nat_type: NatType,
    pub_addr: SocketAddr,
}

impl Peer {
    pub fn get_pub_addr(&self) -> SocketAddr {
        self.pub_addr
    }

    pub fn get_email(&self) -> String {
        self.email.clone()
    }

    pub fn to_message_bytes(&self) -> Bytes {
        let mut bytes = vec![];

        bytes.extend(self.email.clone().as_bytes().to_vec());
        bytes.push(b'\n');
        bytes.extend(nat_type_2_string(self.nat_type).as_bytes().to_vec());
        bytes.push(b'\n');
        bytes.extend(self.pub_addr.to_string().as_bytes().to_vec());

        bytes.into()
    }
}

pub fn string_2_nat_type(value: String) -> NatType {
    match value.as_str() {
        "UdpBlocked" => NatType::UdpBlocked,
        "OpenInternet" => NatType::OpenInternet,
        "SymmetricUdpFirewall" => NatType::SymmetricUdpFirewall,
        "FullCone" => NatType::FullCone,
        "RestrictedCone" => NatType::RestrictedCone,
        "PortRestrictedCone" => NatType::PortRestrictedCone,
        "Symmetric" => NatType::Symmetric,
        _ => NatType::Unknown,
    }
}

pub fn nat_type_2_string(nat_type: NatType) -> String {
    match nat_type {
        NatType::UdpBlocked => "UdpBlocked".to_string(),
        NatType::OpenInternet => "OpenInternet".to_string(),
        NatType::SymmetricUdpFirewall => "SymmetricUdpFirewall".to_string(),
        NatType::FullCone => "FullCone".to_string(),
        NatType::RestrictedCone => "RestrictedCone".to_string(),
        NatType::PortRestrictedCone => "PortRestrictedCone".to_string(),
        NatType::Symmetric => "Symmetric".to_string(),
        NatType::Unknown => "Unknown".to_string(),
    }
}

#[repr(u8)]
enum PacketHeader {
    Register,
    Query,
}

impl TryFrom<u8> for PacketHeader {
    type Error = PacketTypeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Register),
            1 => Ok(Self::Query),
            _ => Err(PacketTypeError::InvalidBytes),
        }
    }
}

pub enum PacketType {
    /// repersenting a register message
    /// ------------------
    /// register
    /// email
    /// nat type
    /// public address
    ///
    Register(Peer),
    /// query the public address of Email
    /// -----------------
    /// query
    /// email
    QueryAddr(String),
}

impl TryFrom<Bytes> for PacketType {
    type Error = PacketTypeError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let lines: Vec<_> = value.split(|v| *v == b'\n').collect();
        if lines.len() < 1 {
            return Err(PacketTypeError::InvalidBytes);
        }

        let header = lines[0];
        if header.len() != 1 {
            return Err(PacketTypeError::InvalidBytes);
        }

        let header = PacketHeader::try_from(header[0])?;

        match header {
            PacketHeader::Register => Self::convert_register(lines),
            PacketHeader::Query => Self::convert_query(lines),
        }
        .map_err(|_| PacketTypeError::InvalidBytes)
    }
}

impl PacketType {
    fn convert_register(bytes: Vec<&[u8]>) -> anyhow::Result<Self> {
        if bytes.len() != 4 {
            return Err(PacketTypeError::InvalidBytes.into());
        }

        let email = String::from_utf8(bytes[1].to_vec())?;
        let nat_type = string_2_nat_type(String::from_utf8(bytes[2].to_vec())?);
        let pub_addr = String::from_utf8(bytes[3].to_vec())?.parse()?;

        Ok(Self::Register(Peer {
            email,
            nat_type,
            pub_addr,
        }))
    }

    fn convert_query(bytes: Vec<&[u8]>) -> anyhow::Result<Self> {
        if bytes.len() != 2 {
            return Err(PacketTypeError::InvalidBytes.into());
        }

        let email = String::from_utf8(bytes[1].to_vec())?;

        Ok(Self::QueryAddr(email))
    }
}

#[derive(Debug, Error)]
pub enum PacketTypeError {
    #[error("invalid bytes")]
    InvalidBytes,
}
