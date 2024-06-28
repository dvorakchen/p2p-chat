mod packets;
mod peer;

pub use packets::*;
pub use peer::*;

// use nat_detect::NatType;
use std::{fmt::Display, ops::Deref};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatType(nat_detect::NatType);

pub const NAT_TYPE_UDP_BLOCKED: NatType = NatType(nat_detect::NatType::UdpBlocked);
pub const NAT_TYPE_OPEN_INTERNET: NatType = NatType(nat_detect::NatType::OpenInternet);
pub const NAT_TYPE_SYMMETRIC_UDP_FIREWALL: NatType =
    NatType(nat_detect::NatType::SymmetricUdpFirewall);
pub const NAT_TYPE_FULL_CONE: NatType = NatType(nat_detect::NatType::FullCone);
pub const NAT_TYPE_RESTRICTED_CONE: NatType = NatType(nat_detect::NatType::RestrictedCone);
pub const NAT_TYPE_PORT_RESTRICTED_CONE: NatType = NatType(nat_detect::NatType::PortRestrictedCone);
pub const NAT_TYPE_SYMMETRIC: NatType = NatType(nat_detect::NatType::Symmetric);
pub const NAT_TYPE_UNKNOW: NatType = NatType(nat_detect::NatType::Unknown);

impl Deref for NatType {
    type Target = nat_detect::NatType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&str> for NatType {
    type Error = PacketTypeError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "UdpBlocked" => Ok(NatType(nat_detect::NatType::UdpBlocked)),
            "OpenInternet" => Ok(NatType(nat_detect::NatType::OpenInternet)),
            "SymmetricUdpFirewall" => Ok(NatType(nat_detect::NatType::SymmetricUdpFirewall)),
            "FullCone" => Ok(NatType(nat_detect::NatType::FullCone)),
            "RestrictedCone" => Ok(NatType(nat_detect::NatType::RestrictedCone)),
            "PortRestrictedCone" => Ok(NatType(nat_detect::NatType::PortRestrictedCone)),
            "Symmetric" => Ok(NatType(nat_detect::NatType::Symmetric)),
            "Unknown" => Ok(NatType(nat_detect::NatType::Symmetric)),
            _ => Err(PacketTypeError::UnknownNatType),
        }
    }
}

impl From<nat_detect::NatType> for NatType {
    fn from(value: nat_detect::NatType) -> Self {
        Self(value)
    }
}

impl Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Debug, Error)]
pub enum PacketTypeError {
    #[error("invalid bytes")]
    InvalidBytes,
    #[error("unknown nat type")]
    UnknownNatType,
    #[error("packet header error, unknow header")]
    HeaderError,
    #[error("has not peer")]
    HasNotPeer,
}
