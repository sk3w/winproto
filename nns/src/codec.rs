use std::io;

use bytes::{Buf, BufMut, BytesMut};
use nom::Offset;
use tokio_util::codec::{Decoder, Encoder};

use crate::{messages::{HandshakeMessage, DataMessage}, parser};

pub struct HandshakeCodec;

impl Decoder for HandshakeCodec {
    type Item = HandshakeMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parser::handshake_message(src) {
            Ok((remainder, msg)) => {
                let cnt = src.offset(remainder);
                src.advance(cnt);
                Ok(Some(msg))
            }
            Err(nom::Err::Incomplete(_needed)) => Ok(None),
            Err(_) => todo!(),
        }
    }
}

impl Encoder<HandshakeMessage> for HandshakeCodec {
    type Error = io::Error;

    fn encode(&mut self, item: HandshakeMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            HandshakeMessage::HandshakeDone { auth_payload } => {
                dst.reserve(5 + auth_payload.len());
                dst.put_slice(&[HandshakeMessage::HANDSHAKE_DONE, 0x01, 0x00]);
                dst.put_u16(auth_payload.len() as u16); // TODO: Ensure payload length doesn't exceed u16::MAX
                dst.put(auth_payload.as_ref());
                Ok(())
            }
            HandshakeMessage::HandshakeError { error_code } => {
                dst.reserve(13);
                dst.put_slice(&[HandshakeMessage::HANDSHAKE_ERROR, 0x01, 0x00]);
                dst.put_u16(8); // Length is always 8
                dst.put_slice(&[0, 0, 0, 0]);
                dst.put_u32(error_code);
                Ok(())
            }
            HandshakeMessage::HandshakeInProgress { auth_payload } => {
                dst.reserve(5 + auth_payload.len());
                dst.put_slice(&[HandshakeMessage::HANDSHAKE_IN_PROGRESS, 0x01, 0x00]);
                dst.put_u16(auth_payload.len() as u16); // TODO: Ensure payload length doesn't exceed u16::MAX
                dst.put(auth_payload.as_ref());
                Ok(())
            }
        }
    }
}

pub struct DataCodec;

impl Decoder for DataCodec {
    type Item = DataMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parser::data_message(src) {
            Ok((remainder, msg)) => {
                let cnt = src.offset(remainder);
                src.advance(cnt);
                Ok(Some(msg))
            }
            Err(nom::Err::Incomplete(_needed)) => Ok(None),
            Err(_) => todo!(),
        }
    }
}

impl Encoder<DataMessage> for DataCodec {
    type Error = io::Error;

    fn encode(&mut self, item: DataMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        assert!(payload_len <= 0x0000fc30);
        dst.reserve(4 + payload_len);
        dst.put_u32_le(payload_len.try_into().unwrap());
        dst.put(item.payload);
        Ok(())
    }
}