use std::net::SocketAddr;

use bytecodec::{
    bytecodec_try_decode, bytecodec_try_encode,
    bytes::{Utf8Decoder, Utf8Encoder},
    null::{NullDecoder, NullEncoder},
    Decode, Encode, ErrorKind, SizedEncode,
};
use trackable::track;

use crate::NatType;

macro_rules! put_newline {
    ($buf: expr, $offset: expr) => {
        $buf[$offset] = b'\n';
        $offset += 1;
    };
}

#[derive(Debug, Clone)]
pub struct Peer {
    email: String,
    nat_type: crate::NatType,
    pub_addr: SocketAddr,
}

impl Peer {
    pub fn new(email: impl AsRef<str>, nat_type: crate::NatType, pub_addr: SocketAddr) -> Self {
        Self {
            email: email.as_ref().to_string(),
            nat_type,
            pub_addr,
        }
    }

    pub fn get_email(&self) -> String {
        self.email.clone()
    }

    pub fn get_nat_type(&self) -> crate::NatType {
        self.nat_type
    }

    pub fn get_pub_addr(&self) -> SocketAddr {
        self.pub_addr
    }
}

#[derive(Default)]
pub struct PeerEncoder {
    email: Utf8Encoder,
    nat_type: NatTypeEncoder,
    pub_addr: PubAddrEncoder,
}

impl Encode for PeerEncoder {
    type Item = Peer;

    fn start_encoding(&mut self, item: Self::Item) -> bytecodec::Result<()> {
        track!(self.email.start_encoding(item.email))?;
        track!(self.nat_type.start_encoding(item.nat_type))?;
        track!(self.pub_addr.start_encoding(item.pub_addr))?;
        Ok(())
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        bytecodec::ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn encode(&mut self, buf: &mut [u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        let mut offset = 0usize;
        bytecodec_try_encode!(self.email, offset, buf, eos);
        put_newline!(buf, offset);
        bytecodec_try_encode!(self.nat_type, offset, buf, eos);
        put_newline!(buf, offset);
        bytecodec_try_encode!(self.pub_addr, offset, buf, eos);

        Ok(offset)
    }

    fn is_idle(&self) -> bool {
        self.email.is_idle() && self.nat_type.is_idle() && self.pub_addr.is_idle()
    }
}

#[derive(Default)]
pub struct PeerDecoder {
    email: Utf8Decoder,
    nat_type: NatTypeDecoder,
    pub_addr: PubAddrDecoder,
}

impl Decode for PeerDecoder {
    type Item = Peer;

    fn decode(&mut self, buf: &[u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        let mut offset = 0;
        let lines: Vec<&[u8]> = buf.split(|v| *v == b'\n').collect();

        let mut sum_offset = 0;
        if lines.len() != 3 {
            Err(ErrorKind::InvalidInput.into())
        } else {
            bytecodec_try_decode!(self.email, offset, lines[0], eos);
            sum_offset += offset;
            offset = 0;
            bytecodec_try_decode!(self.nat_type, offset, lines[1], eos);
            sum_offset += offset;
            offset = 0;
            bytecodec_try_decode!(self.pub_addr, offset, lines[2], eos);
            sum_offset += offset;
            sum_offset += 2; /* this 2 is two of newlines \n */

            Ok(sum_offset)
        }
    }

    fn finish_decoding(&mut self) -> bytecodec::Result<Self::Item> {
        let email = self.email.finish_decoding()?;
        let nat_type = self.nat_type.finish_decoding()?;
        let pub_addr = self.pub_addr.finish_decoding()?;

        Ok(Peer {
            email,
            nat_type,
            pub_addr,
        })
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        if let Some(count) = self
            .email
            .requiring_bytes()
            .add_for_decoding(self.nat_type.requiring_bytes())
            .add_for_decoding(self.pub_addr.requiring_bytes())
            .to_u64()
        {
            bytecodec::ByteCount::Finite(count + 2) /* this 2 is two bytes of newlines \n */
        } else {
            bytecodec::ByteCount::Unknown
        }
    }
}

impl SizedEncode for PeerEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.email.exact_requiring_bytes()
            + self.nat_type.exact_requiring_bytes()
            + self.pub_addr.exact_requiring_bytes()
            + 2 /* this 2 is two newlines \n */
    }
}

#[derive(Default)]
pub struct NatTypeEncoder(Utf8Encoder);

impl Encode for NatTypeEncoder {
    type Item = NatType;

    fn encode(&mut self, buf: &mut [u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.encode(buf, eos)
    }

    fn start_encoding(&mut self, item: Self::Item) -> bytecodec::Result<()> {
        self.0.start_encoding(item.to_string())
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        bytecodec::ByteCount::Finite(self.exact_requiring_bytes())
    }
}

#[derive(Default)]
pub struct NatTypeDecoder(Utf8Decoder);

impl Decode for NatTypeDecoder {
    type Item = NatType;

    fn decode(&mut self, buf: &[u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.decode(buf, eos)
    }

    fn finish_decoding(&mut self) -> bytecodec::Result<Self::Item> {
        self.0
            .finish_decoding()
            .map(|v| NatType::try_from(v.as_str()).unwrap())
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

impl SizedEncode for NatTypeEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.0.exact_requiring_bytes()
    }
}

#[derive(Debug, Default)]
pub struct PubAddrEncoder(Utf8Encoder);

impl Encode for PubAddrEncoder {
    type Item = SocketAddr;

    fn encode(&mut self, buf: &mut [u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.encode(buf, eos)
    }

    fn start_encoding(&mut self, item: Self::Item) -> bytecodec::Result<()> {
        self.0.start_encoding(item.to_string())
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

#[derive(Debug, Default)]
pub struct PubAddrDecoder(Utf8Decoder);

impl Decode for PubAddrDecoder {
    type Item = SocketAddr;

    fn decode(&mut self, buf: &[u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.decode(buf, eos)
    }

    fn finish_decoding(&mut self) -> bytecodec::Result<Self::Item> {
        self.0.finish_decoding().map(|v| v.parse().unwrap())
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

impl SizedEncode for PubAddrEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.0.exact_requiring_bytes()
    }
}

#[derive(Debug, Default)]
pub struct QueryListEncoder(NullEncoder);

impl Encode for QueryListEncoder {
    type Item = ();

    fn encode(&mut self, buf: &mut [u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.encode(buf, eos)
    }

    fn start_encoding(&mut self, item: Self::Item) -> bytecodec::Result<()> {
        self.0.start_encoding(item)
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

impl SizedEncode for QueryListEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.0.exact_requiring_bytes()
    }
}

#[derive(Debug, Default)]
pub struct ListDecoder(NullDecoder);

impl Decode for ListDecoder {
    type Item = ();

    fn decode(&mut self, buf: &[u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.decode(buf, eos)
    }

    fn finish_decoding(&mut self) -> bytecodec::Result<Self::Item> {
        self.0.finish_decoding()
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

#[derive(Debug, Default)]
pub struct PingEncoder(NullEncoder);

impl Encode for PingEncoder {
    type Item = ();

    fn encode(&mut self, buf: &mut [u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.encode(buf, eos)
    }

    fn start_encoding(&mut self, item: Self::Item) -> bytecodec::Result<()> {
        self.0.start_encoding(item)
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

impl SizedEncode for PingEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.0.exact_requiring_bytes()
    }
}

#[derive(Debug, Default)]
pub struct PingDecoder(NullDecoder);

impl Decode for PingDecoder {
    type Item = ();

    fn decode(&mut self, buf: &[u8], eos: bytecodec::Eos) -> bytecodec::Result<usize> {
        self.0.decode(buf, eos)
    }

    fn finish_decoding(&mut self) -> bytecodec::Result<Self::Item> {
        self.0.finish_decoding()
    }

    fn requiring_bytes(&self) -> bytecodec::ByteCount {
        self.0.requiring_bytes()
    }
}

#[cfg(test)]
mod test {

    use bytecodec::{DecodeExt, EncodeExt};

    use crate::{NatType, NAT_TYPE_PORT_RESTRICTED_CONE};

    use super::{Peer, PeerDecoder, PeerEncoder};

    #[test]
    fn test_encoder() {
        let mut encoder = PeerEncoder::default();

        const EXPECTED_EMAIL: &str = "a";
        const EXPECTED_NAT_TYPE: NatType = NAT_TYPE_PORT_RESTRICTED_CONE;
        const EXPECTED_PUB_ADDR: &str = "127.0.0.1:9989";

        let bytes = encoder
            .encode_into_bytes(Peer {
                email: EXPECTED_EMAIL.to_string(),
                nat_type: EXPECTED_NAT_TYPE,
                pub_addr: EXPECTED_PUB_ADDR.parse().unwrap(),
            })
            .unwrap();

        let mut expected_result = Vec::new();
        expected_result.extend_from_slice(EXPECTED_EMAIL.as_bytes());
        expected_result.push(b'\n');
        expected_result.extend_from_slice(EXPECTED_NAT_TYPE.to_string().as_bytes());
        expected_result.push(b'\n');
        expected_result.extend_from_slice(EXPECTED_PUB_ADDR.as_bytes());

        assert_eq!(bytes, expected_result);
    }

    #[test]
    fn test_decoder() {
        let mut decoder = PeerDecoder::default();

        const EXPECTED_EMAIL: &str = "a";
        const EXPECTED_NAT_TYPE: NatType = NAT_TYPE_PORT_RESTRICTED_CONE;
        const EXPECTED_PUB_ADDR: &str = "127.0.0.1:9989";

        let mut bytes = Vec::new();
        bytes.extend_from_slice(EXPECTED_EMAIL.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(EXPECTED_NAT_TYPE.to_string().as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(EXPECTED_PUB_ADDR.as_bytes());

        let peer = decoder.decode_from_bytes(&bytes).unwrap();

        assert_eq!(peer.email, EXPECTED_EMAIL.to_string());
        assert_eq!(peer.nat_type, EXPECTED_NAT_TYPE);
        assert_eq!(peer.pub_addr, EXPECTED_PUB_ADDR.parse().unwrap());
    }
}
