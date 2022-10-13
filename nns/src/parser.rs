use bytes::Bytes;
use nom::{
    branch::alt,
    bytes::streaming::tag,
    combinator::{map, verify},
    multi::length_data,
    number::streaming::{be_u16, be_u32, le_u32},
    sequence::preceded,
    IResult,
};

use crate::messages::{DataMessage, HandshakeMessage};

pub fn handshake_message(input: &[u8]) -> IResult<&[u8], HandshakeMessage> {
    alt((handshake_done, handshake_error, handshake_in_progress))(input)
}

pub fn handshake_done(input: &[u8]) -> IResult<&[u8], HandshakeMessage> {
    preceded(
        tag([0x14, 0x01, 0x00]),
        map(length_data(be_u16), |b: &[u8]| {
            HandshakeMessage::HandshakeDone {
                auth_payload: b.to_vec(),
            }
        }),
    )(input)
}

pub fn handshake_error(input: &[u8]) -> IResult<&[u8], HandshakeMessage> {
    preceded(
        tag([0x15, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]),
        map(be_u32, |error_code| HandshakeMessage::HandshakeError {
            error_code,
        }),
    )(input)
}

pub fn handshake_in_progress(input: &[u8]) -> IResult<&[u8], HandshakeMessage> {
    preceded(
        tag([0x16, 0x01, 0x00]),
        map(length_data(be_u16), |b: &[u8]| {
            HandshakeMessage::HandshakeInProgress {
                auth_payload: b.to_vec(),
            }
        }),
    )(input)
}

pub fn data_message(input: &[u8]) -> IResult<&[u8], DataMessage> {
    map(
        verify(length_data(le_u32), |b: &[u8]| b.len() <= 0x0000fc30),
        |b: &[u8]| DataMessage {
            payload: Bytes::copy_from_slice(b),
        },
    )(input)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn parse_handshake_done() {
        let input = hex!(
            "14 01 00 00 1d a1 1b 30 19 a0 03 0a 01 00 a3 12"
            "04 10 01 00 00 00 70 07 4c 98 87 7d b8 15 00 00"
            "00 00"
        )
        .as_ref();

        let auth_payload = hex!(
            "a1 1b 30 19 a0 03 0a 01 00 a3 12 04 10 01 00 00"
            "00 70 07 4c 98 87 7d b8 15 00 00 00 00"
        )
        .to_vec();

        let expected = HandshakeMessage::HandshakeDone { auth_payload };
        let (_remainder, output) = handshake_message(input).unwrap();
        assert_eq!(output, expected)
    }

    #[test]
    fn parse_handhshake_in_progress() {
        let input = hex!(
            "16 01 00 00 77 60 75 06 06 2b 06 01 05 05 02 a0"
            "6b 30 69 a0 30 30 2e 06 0a 2b 06 01 04 01 82 37"
            "02 02 0a 06 09 2a 86 48 82 f7 12 01 02 02 06 09"
            "2a 86 48 86 f7 12 01 02 02 06 0a 2b 06 01 04 01"
            "82 37 02 02 1e a2 35 04 33 4e 54 4c 4d 53 53 50"
            "00 01 00 00 00 b7 b2 08 e2 09 00 09 00 2a 00 00"
            "00 02 00 02 00 28 00 00 00 0a 00 39 38 00 00 00"
            "0f 44 43 57 49 4e 44 4f 4d 41 49 4e"
        )
        .as_ref();

        let auth_payload = hex!(
            "60 75 06 06 2b 06 01 05 05 02 a0 6b 30 69 a0 30"
            "30 2e 06 0a 2b 06 01 04 01 82 37 02 02 0a 06 09"
            "2a 86 48 82 f7 12 01 02 02 06 09 2a 86 48 86 f7"
            "12 01 02 02 06 0a 2b 06 01 04 01 82 37 02 02 1e"
            "a2 35 04 33 4e 54 4c 4d 53 53 50 00 01 00 00 00"
            "b7 b2 08 e2 09 00 09 00 2a 00 00 00 02 00 02 00"
            "28 00 00 00 0a 00 39 38 00 00 00 0f 44 43 57 49"
            "4e 44 4f 4d 41 49 4e"
        )
        .to_vec();

        let expected = HandshakeMessage::HandshakeInProgress { auth_payload };
        let (_remainder, output) = handshake_message(input).unwrap();
        assert_eq!(output, expected)
    }

    #[test]
    fn parse_data_message() {
        let input = hex!(
            "11 00 00 00 01 00 00 00 5e 8a 7f 79 8b 77 5e 61"
            "01 00 00 00 dd"
        ).as_ref();

        let payload = hex!(
            "01 00 00 00 5e 8a 7f 79 8b 77 5e 61 01 00 00 00"
            "dd"
        ).as_ref();

        let expected = DataMessage { payload: Bytes::from(payload) };
        let (_remainder, output) = data_message(input).unwrap();
        assert_eq!(output, expected);
    }
}
