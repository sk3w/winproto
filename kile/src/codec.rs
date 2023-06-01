use std::io;

use bytes::{Buf, BufMut, BytesMut};
use nom::Offset;
use rasn::der;
use rasn_kerberos::{AsRep, AsReq, KrbError, TgsRep, TgsReq};
use tokio_util::codec::{Decoder, Encoder};

use crate::{frame::KdcFrame, parser};

pub struct KdcCodec;

impl Decoder for KdcCodec {
    type Item = KdcFrame;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parser::kdc_frame(src) {
            Ok((second, frame)) => {
                src.advance(src.offset(second));
                Ok(Some(frame))
            }
            Err(nom::Err::Incomplete(_)) => Ok(None),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to decode KdcFrame",
            )),
        }
    }
}

impl Encoder<KdcFrame> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: KdcFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            KdcFrame::AsReq(item) => self.encode(item, dst),
            KdcFrame::AsRep(item) => self.encode(item, dst),
            KdcFrame::TgsReq(item) => self.encode(item, dst),
            KdcFrame::TgsRep(item) => self.encode(item, dst),
            KdcFrame::KrbError(item) => self.encode(item, dst),
        }
    }
}

impl Encoder<AsReq> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: AsReq, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Encoding failed for AsReq"))?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<AsRep> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: AsRep, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Encoding failed for AsRep"))?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<TgsReq> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TgsReq, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Encoding failed for TgsReq")
        })?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<TgsRep> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TgsRep, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Encoding failed for TgsRep")
        })?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<KrbError> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: KrbError, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Encoding failed for KrbError")
        })?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}
