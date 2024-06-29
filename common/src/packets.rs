use bytecodec::{
    bytecodec_try_decode,
    bytes::{Utf8Decoder, Utf8Encoder},
    fixnum::{U8Decoder, U8Encoder},
    ByteCount, Decode, DecodeExt, Encode, SizedEncode,
};

use crate::{
    peer::Peer, ListDecoder, PacketTypeError, PeerDecoder, PeerEncoder, PingDecoder, PingEncoder,
    QueryListEncoder,
};
use trackable::track;

const HEADER_BYTES_LEN: usize = 1;
const NEWLINE_BYTES_LEN: usize = 1;

/// Packet wrapped type of message on the top
///
/// ----------------------------
/// <header> packet type 0: query; 1: register
/// <message> different message depends header
#[derive(Debug)]
pub enum PacketType {
    /// query peer information of email from server
    Query(String),
    /// register the current peer information to server
    Register(Peer),
    Ping,
    Peer(Peer),
    /// query all activity peers
    QueryList,
    Message(String),
}

#[derive(Default)]
pub struct PacketTypeEncoder {
    packet_type: Option<PacketTypeEncodeDecoderType>,
    header_encoder: U8Encoder,
    query_encoder: Utf8Encoder,
    register_encoder: PeerEncoder,
    ping_encoder: PingEncoder,
    peer_encoder: PeerEncoder,
    query_list_encoder: QueryListEncoder,
    message_encoder: Utf8Encoder,
}

#[derive(Clone, Copy)]
enum PacketTypeEncodeDecoderType {
    Query = 0,
    Register = 1,
    Ping = 2,
    Peer = 3,
    QueryList = 4,
    Message = 5,
}

impl TryFrom<u8> for PacketTypeEncodeDecoderType {
    type Error = PacketTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Query),
            1 => Ok(Self::Register),
            2 => Ok(Self::Ping),
            3 => Ok(Self::Peer),
            4 => Ok(Self::QueryList),
            5 => Ok(Self::Message),
            _ => Err(PacketTypeError::HeaderError),
        }
    }
}

macro_rules! try_encode {
    ($encoder: expr, $buf: expr, $eos: expr) => {
        $encoder.encode(&mut $buf[HEADER_BYTES_LEN + NEWLINE_BYTES_LEN..], $eos)
    };
}
macro_rules! try_start_encode {
    ($self: expr, $vant:expr, $encoder: expr, $encode_item: expr) => {
        use PacketTypeEncodeDecoderType::*;
        $self.header_encoder.start_encoding($vant as u8)?;
        $self.packet_type = Some($vant);
        $encoder.start_encoding($encode_item)?;
    };
}

impl Encode for PacketTypeEncoder {
    type Item = PacketType;

    fn encode(&mut self, buf: &mut [u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.header_encoder
            .encode(&mut buf[..HEADER_BYTES_LEN], eos)?;
        buf[HEADER_BYTES_LEN] = b'\n';

        match self.packet_type.as_ref().unwrap() {
            &PacketTypeEncodeDecoderType::Query => try_encode!(self.query_encoder, buf, eos),
            &PacketTypeEncodeDecoderType::Register => try_encode!(self.register_encoder, buf, eos),
            &PacketTypeEncodeDecoderType::Ping => try_encode!(self.ping_encoder, buf, eos),
            &PacketTypeEncodeDecoderType::Peer => try_encode!(self.peer_encoder, buf, eos),
            &PacketTypeEncodeDecoderType::QueryList => {
                try_encode!(self.query_list_encoder, buf, eos)
            }
            &PacketTypeEncodeDecoderType::Message => try_encode!(self.message_encoder, buf, eos),
        }
    }

    fn start_encoding(&mut self, item: Self::Item) -> bytecodec::Result<()> {
        match item {
            Self::Item::Query(email) => {
                try_start_encode!(self, Query, self.query_encoder, email);
            }
            Self::Item::Register(peer) => {
                try_start_encode!(self, Register, self.register_encoder, peer);
            }
            Self::Item::Ping => {
                try_start_encode!(self, Ping, self.ping_encoder, ());
            }
            Self::Item::Peer(peer) => {
                try_start_encode!(self, Peer, self.peer_encoder, peer);
            }
            Self::Item::QueryList => {
                try_start_encode!(self, QueryList, self.query_list_encoder, ());
            }
            Self::Item::Message(message) => {
                try_start_encode!(self, Message, self.message_encoder, message);
            }
        }

        Ok(())
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        bytecodec::ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.header_encoder.is_idle()
            && match self.packet_type.as_ref().unwrap() {
                &PacketTypeEncodeDecoderType::Query => self.query_encoder.is_idle(),
                &PacketTypeEncodeDecoderType::Register => self.register_encoder.is_idle(),
                &PacketTypeEncodeDecoderType::Ping => self.ping_encoder.is_idle(),
                &PacketTypeEncodeDecoderType::Peer => self.peer_encoder.is_idle(),
                &PacketTypeEncodeDecoderType::QueryList => self.query_list_encoder.is_idle(),
                &PacketTypeEncodeDecoderType::Message => self.message_encoder.is_idle(),
            }
    }
}

impl SizedEncode for PacketTypeEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.header_encoder.exact_requiring_bytes()
            + match self.packet_type.as_ref().unwrap() {
                &PacketTypeEncodeDecoderType::Query => self.query_encoder.exact_requiring_bytes(),
                &PacketTypeEncodeDecoderType::Register => {
                    self.register_encoder.exact_requiring_bytes()
                }
                &PacketTypeEncodeDecoderType::Ping => self.ping_encoder.exact_requiring_bytes(),
                &PacketTypeEncodeDecoderType::Peer => self.peer_encoder.exact_requiring_bytes(),
                &PacketTypeEncodeDecoderType::QueryList => {
                    self.query_list_encoder.exact_requiring_bytes()
                }
                &PacketTypeEncodeDecoderType::Message => {
                    self.message_encoder.exact_requiring_bytes()
                }
            }
            + NEWLINE_BYTES_LEN as u64
    }
}

#[derive(Default)]
pub struct PacketTypeDecoder {
    packet_type: Option<PacketTypeEncodeDecoderType>,
    header_decoder: U8Decoder,
    query_decoder: Utf8Decoder,
    register_decoder: PeerDecoder,
    ping_decoder: PingDecoder,
    peer_decoder: PeerDecoder,
    list_decoder: ListDecoder,
    message_decoder: Utf8Decoder,
}

impl Decode for PacketTypeDecoder {
    type Item = PacketType;

    fn decode(&mut self, buf: &[u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        let mut offset = 0;
        let header = buf[0];
        let header = self.header_decoder.decode_from_bytes(&[header])?;

        self.packet_type = Some(header.try_into().unwrap());

        offset += self.header_decoder.decode(&[header], eos)?;
        offset += NEWLINE_BYTES_LEN;

        match self.packet_type.as_ref().unwrap() {
            &PacketTypeEncodeDecoderType::Query => {
                bytecodec_try_decode!(self.query_decoder, offset, buf, eos);
            }
            &PacketTypeEncodeDecoderType::Register => {
                bytecodec_try_decode!(self.register_decoder, offset, buf, eos);
            }
            &PacketTypeEncodeDecoderType::Ping => {
                bytecodec_try_decode!(self.ping_decoder, offset, buf, eos);
            }
            &PacketTypeEncodeDecoderType::Peer => {
                bytecodec_try_decode!(self.peer_decoder, offset, buf, eos);
            }
            &PacketTypeEncodeDecoderType::QueryList => {
                bytecodec_try_decode!(self.list_decoder, offset, buf, eos);
            }
            &PacketTypeEncodeDecoderType::Message => {
                bytecodec_try_decode!(self.message_decoder, offset, buf, eos);
            }
        }

        Ok(offset)
    }

    fn finish_decoding(&mut self) -> bytecodec::Result<Self::Item> {
        match self.packet_type.as_ref().unwrap() {
            &PacketTypeEncodeDecoderType::Query => {
                Ok(Self::Item::Query(self.query_decoder.finish_decoding()?))
            }
            &PacketTypeEncodeDecoderType::Register => Ok(Self::Item::Register(
                self.register_decoder.finish_decoding()?,
            )),
            &PacketTypeEncodeDecoderType::Ping => Ok(Self::Item::Ping),
            &PacketTypeEncodeDecoderType::Peer => {
                Ok(Self::Item::Peer(self.peer_decoder.finish_decoding()?))
            }
            &PacketTypeEncodeDecoderType::QueryList => Ok(Self::Item::QueryList),
            &PacketTypeEncodeDecoderType::Message => {
                Ok(Self::Item::Message(self.message_decoder.finish_decoding()?))
            }
        }
    }

    fn requiring_bytes(&self) -> ByteCount {
        match self.packet_type.as_ref().unwrap() {
            &PacketTypeEncodeDecoderType::Query => self.query_decoder.requiring_bytes(),
            &PacketTypeEncodeDecoderType::Register => self.register_decoder.requiring_bytes(),
            &PacketTypeEncodeDecoderType::Ping => self.ping_decoder.requiring_bytes(),
            &PacketTypeEncodeDecoderType::Peer => self.peer_decoder.requiring_bytes(),
            &PacketTypeEncodeDecoderType::QueryList => self.list_decoder.requiring_bytes(),
            &PacketTypeEncodeDecoderType::Message => self.message_decoder.requiring_bytes(),
        }
        .add_for_decoding(self.header_decoder.requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.header_decoder.is_idle()
            && match self.packet_type.as_ref().unwrap() {
                &PacketTypeEncodeDecoderType::Query => self.query_decoder.is_idle(),
                &PacketTypeEncodeDecoderType::Register => self.register_decoder.is_idle(),
                &PacketTypeEncodeDecoderType::Ping => self.ping_decoder.is_idle(),
                &PacketTypeEncodeDecoderType::Peer => self.peer_decoder.is_idle(),
                &PacketTypeEncodeDecoderType::QueryList => self.list_decoder.is_idle(),
                &PacketTypeEncodeDecoderType::Message => self.message_decoder.is_idle(),
            }
    }
}

#[cfg(test)]
mod test {
    use bytecodec::{DecodeExt, EncodeExt};

    use crate::{
        packets::PacketTypeEncodeDecoderType, NatType, PacketType, PacketTypeDecoder,
        PacketTypeEncoder, Peer, NAT_TYPE_PORT_RESTRICTED_CONE,
    };

    #[test]
    fn test_encode_query() {
        // arrage
        let mut encoder = PacketTypeEncoder::default();

        const EXPECTED_EMAIL: &str = "a";

        //  action
        let bytes = encoder
            .encode_into_bytes(PacketType::Query(EXPECTED_EMAIL.to_string()))
            .unwrap();

        let mut expected_result = Vec::new();
        expected_result.push(PacketTypeEncodeDecoderType::Query as u8);
        expected_result.push(b'\n');
        expected_result.extend_from_slice(EXPECTED_EMAIL.as_bytes());

        //  assert
        assert_eq!(bytes, expected_result);
    }

    #[test]
    fn test_encode_register() {
        // arrage
        let mut encoder = PacketTypeEncoder::default();

        const EXPECTED_EMAIL: &str = "a";
        const EXPECTED_NAT_TYPE: NatType = NAT_TYPE_PORT_RESTRICTED_CONE;
        const EXPECTED_PUB_ADDR: &str = "119.34.161.150:4548";

        let bytes = encoder
            .encode_into_bytes(PacketType::Register(Peer::new(
                EXPECTED_EMAIL,
                EXPECTED_NAT_TYPE,
                EXPECTED_PUB_ADDR.parse().unwrap(),
            )))
            .unwrap();

        let mut expected_result = Vec::new();
        expected_result.push(PacketTypeEncodeDecoderType::Register as u8);
        expected_result.push(b'\n');
        expected_result.extend_from_slice(EXPECTED_EMAIL.as_bytes());
        expected_result.push(b'\n');
        expected_result.extend_from_slice(EXPECTED_NAT_TYPE.to_string().as_bytes());
        expected_result.push(b'\n');
        expected_result.extend_from_slice(EXPECTED_PUB_ADDR.as_bytes());

        assert_eq!(bytes, expected_result);
    }

    #[test]
    fn test_decode_query() {
        // arrage
        let mut decoder = PacketTypeDecoder::default();

        const EXPECTED_EMAIL: &str = "a";
        let mut bytes = Vec::new();
        bytes.push(PacketTypeEncodeDecoderType::Query as u8);
        bytes.push(b'\n');
        bytes.extend_from_slice(EXPECTED_EMAIL.as_bytes());

        //  action
        let pack = decoder.decode_from_bytes(&bytes).unwrap();

        //  assert
        assert!(if let PacketType::Query(email) = pack {
            assert_eq!(email, EXPECTED_EMAIL);
            true
        } else {
            false
        });
    }

    #[test]
    fn test_decode_register() {
        // arrage
        let mut decoder = PacketTypeDecoder::default();

        const EXPECTED_EMAIL: &str = "a";
        const EXPECTED_NAT_TYPE: NatType = NAT_TYPE_PORT_RESTRICTED_CONE;
        const EXPECTED_PUB_ADDR: &str = "119.34.161.150:4548";

        let mut bytes = Vec::new();
        bytes.push(PacketTypeEncodeDecoderType::Register as u8);
        bytes.push(b'\n');
        bytes.extend_from_slice(EXPECTED_EMAIL.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(EXPECTED_NAT_TYPE.to_string().as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(EXPECTED_PUB_ADDR.as_bytes());

        let pack = decoder.decode_from_bytes(&bytes).unwrap();

        assert!(if let PacketType::Register(peer) = pack {
            assert_eq!(peer.get_email(), EXPECTED_EMAIL);
            assert_eq!(peer.get_nat_type(), EXPECTED_NAT_TYPE);
            assert_eq!(peer.get_email(), EXPECTED_EMAIL);
            true
        } else {
            false
        })
    }

    #[test]
    fn test_encode_ping() {
        let mut encoder = PacketTypeEncoder::default();

        let expected_result = vec![PacketTypeEncodeDecoderType::Ping as u8, b'\n'];
        let ping = PacketType::Ping;

        let bytes = encoder.encode_into_bytes(ping).unwrap();

        assert_eq!(expected_result, bytes);
    }

    #[test]
    fn test_decode_ping() {
        let mut decoder = PacketTypeDecoder::default();

        let bytes = vec![PacketTypeEncodeDecoderType::Ping as u8, b'\n'];

        let packet = decoder.decode_from_bytes(&bytes).unwrap();

        assert!(if let PacketType::Ping = packet {
            true
        } else {
            false
        });
    }

    #[test]
    fn test_encode_list() {
        let mut encoder = PacketTypeEncoder::default();

        let expected_result = vec![PacketTypeEncodeDecoderType::QueryList as u8, b'\n'];
        let list = PacketType::QueryList;

        let bytes = encoder.encode_into_bytes(list).unwrap();

        assert_eq!(expected_result, bytes);
    }

    #[test]
    fn test_decode_list() {
        let mut decoder = PacketTypeDecoder::default();

        let bytes = vec![PacketTypeEncodeDecoderType::QueryList as u8, b'\n'];

        let packet = decoder.decode_from_bytes(&bytes).unwrap();

        assert!(if let PacketType::QueryList = packet {
            true
        } else {
            false
        });
    }

    #[test]
    fn test_encode_peer() {
        let mut encoder = PacketTypeEncoder::default();

        const EXPECTED_EMAIL: &str = "a";
        const EXPECTED_NAT_TYPE: NatType = NAT_TYPE_PORT_RESTRICTED_CONE;
        const EXPECTED_PUB_ADDR: &str = "119.34.161.150:4548";

        let bytes = encoder
            .encode_into_bytes(PacketType::Peer(Peer::new(
                EXPECTED_EMAIL,
                EXPECTED_NAT_TYPE,
                EXPECTED_PUB_ADDR.parse().unwrap(),
            )))
            .unwrap();

        let mut expected_result = vec![PacketTypeEncodeDecoderType::Peer as u8, b'\n'];
        expected_result.extend(EXPECTED_EMAIL.as_bytes());
        expected_result.push(b'\n');
        expected_result.extend(EXPECTED_NAT_TYPE.to_string().as_bytes());
        expected_result.push(b'\n');
        expected_result.extend(EXPECTED_PUB_ADDR.as_bytes());

        assert_eq!(expected_result, bytes);
    }

    #[test]
    fn test_decode_peer() {
        let mut decoder = PacketTypeDecoder::default();

        const EXPECTED_EMAIL: &str = "a";
        const EXPECTED_NAT_TYPE: NatType = NAT_TYPE_PORT_RESTRICTED_CONE;
        const EXPECTED_PUB_ADDR: &str = "119.34.161.150:4548";

        let mut bytes = vec![PacketTypeEncodeDecoderType::Peer as u8, b'\n'];
        bytes.extend(EXPECTED_EMAIL.as_bytes());
        bytes.push(b'\n');
        bytes.extend(EXPECTED_NAT_TYPE.to_string().as_bytes());
        bytes.push(b'\n');
        bytes.extend(EXPECTED_PUB_ADDR.as_bytes());

        let packet = decoder.decode_from_bytes(&bytes).unwrap();

        assert!(if let PacketType::Peer(peer) = packet {
            assert_eq!(peer.get_email(), EXPECTED_EMAIL);
            assert_eq!(peer.get_nat_type(), EXPECTED_NAT_TYPE);
            assert_eq!(peer.get_pub_addr(), EXPECTED_PUB_ADDR.parse().unwrap());

            true
        } else {
            false
        });
    }
}
