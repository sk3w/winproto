use nom::{
    branch::alt,
    combinator::{into, map_res},
    multi::length_data,
    number::streaming::be_u32,
    IResult,
};
use rasn::der;
use rasn_kerberos::{AsRep, AsReq, KrbError, TgsRep, TgsReq};

use crate::KdcFrame;

pub fn kdc_frame(input: &[u8]) -> IResult<&[u8], KdcFrame> {
    alt((
        into(as_req),
        into(as_rep),
        into(tgs_req),
        into(tgs_rep),
        into(krb_error),
    ))(input)
}

fn as_req(input: &[u8]) -> IResult<&[u8], AsReq> {
    map_res(length_data(be_u32), |s| der::decode(s))(input)
}

fn as_rep(input: &[u8]) -> IResult<&[u8], AsRep> {
    map_res(length_data(be_u32), |s| der::decode(s))(input)
}

fn tgs_req(input: &[u8]) -> IResult<&[u8], TgsReq> {
    map_res(length_data(be_u32), |s| der::decode(s))(input)
}

fn tgs_rep(input: &[u8]) -> IResult<&[u8], TgsRep> {
    map_res(length_data(be_u32), |s| der::decode(s))(input)
}

fn krb_error(input: &[u8]) -> IResult<&[u8], KrbError> {
    map_res(length_data(be_u32), |s| der::decode(s))(input)
}

#[cfg(test)]
mod tests {
    use rasn::{ber, types::Class, Decoder, Encoder, Tag};
    use rasn_kerberos::KerberosFlags;

    #[test]
    fn kerberos_flags_dec() {
        let input = b"\x03\x05\x00\x40\x81\x00\x00";
        let mut decoder = ber::de::Decoder::new(input, ber::de::DecoderOptions::ber());
        let output = decoder
            .decode_bit_string(Tag::new(Class::Universal, 3))
            .unwrap();
        let expected = KerberosFlags::from_vec([0x40, 0x81, 0x00, 0x00].to_vec());
        assert_eq!(output, expected)
    }

    #[test]
    fn kerberos_flags_enc() {
        let bitstring = KerberosFlags::from_vec([0x40, 0x81, 0x00, 0x00].to_vec());
        let mut encoder = ber::enc::Encoder::new(ber::enc::EncoderOptions::ber());
        encoder
            .encode_bit_string(Tag::new(Class::Universal, 3), &bitstring)
            .unwrap();
        assert_eq!(
            encoder.output(),
            vec![0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x00]
        )
    }
}
