extern crate std;

use bytes::{Buf, BufMut, BytesMut};
use nom::Offset;
use std::{io, println};
use tokio_util::codec::{Decoder, Encoder};

use crate::{frame::NmfFrame, parser, records::*};

pub struct NmfCodec;

impl NmfCodec {
    pub fn new() -> Self {
        Self {}
    }
}

impl Decoder for NmfCodec {
    type Item = NmfFrame;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parser::nmf_frame(src) {
            Ok((tail, f)) => {
                let count = src.offset(tail);
                src.advance(count);
                Ok(Some(f))
            }
            Err(nom::Err::Incomplete(_needed)) => Ok(None),
            //Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "Expected NmfFrame")),
            //Err(_) => Ok(Some(NmfFrame::Unknown(src.clone().freeze()))),
            Err(e) => {
                println!("Error: {:?}", &e);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Expected NmfFrame",
                ))
            }
        }
    }
}

impl Encoder<NmfFrame> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, item: NmfFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            NmfFrame::Preamble(msg) => self.encode(msg, dst),
            NmfFrame::PreambleEnd(msg) => self.encode(msg, dst),
            NmfFrame::PreambleAck(msg) => self.encode(msg, dst),
            NmfFrame::UpgradeRequest(_) => todo!(),
            NmfFrame::UpgradeResponse(_) => todo!(),
            NmfFrame::End(msg) => self.encode(msg, dst),
            NmfFrame::SizedEnvelope(msg) => self.encode(msg, dst),
            NmfFrame::UnsizedEnvelope(_) => todo!(),
            NmfFrame::Fault(msg) => self.encode(msg, dst),
            NmfFrame::Unknown(_) => todo!(),
        }
    }
}
impl Encoder<PreambleMessage> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, item: PreambleMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(13 + item.via.inner_bytes().len());
        dst.put_slice(&[
            VersionRecord::RECORD_TYPE,
            VersionRecord::MAJOR_VERSION,
            VersionRecord::MINOR_VERSION,
        ]);
        dst.put_slice(&[ModeRecord::RECORD_TYPE, (item.mode as u8)]);
        dst.put_u8(ViaRecord::RECORD_TYPE);
        dst.put_slice(&encode_record_size(item.via.inner_bytes().len())); // max length of 5 bytes
        dst.put_slice(item.via.inner_bytes());
        dst.put_u8(KnownEncodingRecord::RECORD_TYPE);
        dst.put_u8(item.encoding as u8);
        Ok(())
    }
}

impl Encoder<PreambleEndRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, _item: PreambleEndRecord, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(1);
        dst.put_u8(PreambleEndRecord::RECORD_TYPE);
        Ok(())
    }
}

impl Encoder<PreambleAckRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, item: PreambleAckRecord, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(1);
        dst.put_u8(PreambleAckRecord::RECORD_TYPE);
        Ok(())
    }
}

impl Encoder<UpgradeRequestRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: UpgradeRequestRecord,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(6 + item.inner_bytes().len());
        dst.put_u8(UpgradeRequestRecord::RECORD_TYPE);
        dst.put_slice(&encode_record_size(item.inner_bytes().len())); // max length of 5 bytes
        dst.put_slice(item.inner_bytes());
        Ok(())
    }
}

impl Encoder<UpgradeResponseRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: UpgradeResponseRecord,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl Encoder<EndRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, item: EndRecord, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(1);
        dst.put_u8(EndRecord::RECORD_TYPE);
        Ok(())
    }
}

impl Encoder<SizedEnvelopeRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, item: SizedEnvelopeRecord, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(6 + item.payload.len());
        dst.put_u8(SizedEnvelopeRecord::RECORD_TYPE);
        dst.put_slice(&encode_record_size(item.payload.len())); // max length of 5 bytes
        dst.put_slice(item.payload.as_slice());
        Ok(())
    }
}

impl Encoder<UnsizedEnvelopeRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: UnsizedEnvelopeRecord,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl Encoder<FaultRecord> for NmfCodec {
    type Error = io::Error;

    fn encode(&mut self, item: FaultRecord, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(6 + item.inner_bytes().len());
        dst.put_u8(FaultRecord::RECORD_TYPE);
        dst.put_slice(&encode_record_size(item.inner_bytes().len())); // max length of 5 bytes
        dst.put_slice(item.inner_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use hex_literal::hex;

    #[test]
    fn decode_preamble_ack_record() {
        let mut codec = NmfCodec::new();
        let mut src = BytesMut::from(&b"\x0b"[..]);
        assert_eq!(
            codec.decode(&mut src).unwrap(),
            Some(NmfFrame::PreambleAck(PreambleAckRecord::default()))
        )
    }

    #[test]
    fn decode_fault_record() {
        let mut codec = NmfCodec::new();
        let mut src = BytesMut::from(
            hex!(
                "08 47 68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73"
                "2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 77"
                "73 2f 32 30 30 36 2f 30 35 2f 66 72 61 6d 69 6e"
                "67 2f 66 61 75 6c 74 73 2f 45 6e 64 70 6f 69 6e"
                "74 4e 6f 74 46 6f 75 6e 64"
            )
            .as_slice(),
        );
        let fault_record = FaultRecord::new(
            "http://schemas.microsoft.com/ws/2006/05/framing/faults/EndpointNotFound",
        );
        assert_eq!(
            codec.decode(&mut src).unwrap(),
            Some(NmfFrame::Fault(fault_record))
        )
    }
}
