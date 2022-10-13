use crate::{structures::AvPairs, AuthenticateMessage, messages::Mic};

use super::{ChallengeMessage, NegotiateFlags, ServerChallenge, Version};
pub use nom::Err as ParserError;
use nom::{
    bytes::complete::{tag, take, take_while},
    combinator::{map, map_opt, map_res, peek, rest, value},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::{preceded, tuple},
    IResult,
};

struct PayloadFields {
    len: u16,
    max_len: u16,
    offset: u32,
}

pub fn negotiate_flags(input: &[u8]) -> IResult<&[u8], NegotiateFlags> {
    let (input, bits) = le_u32(input)?;
    let flags = NegotiateFlags::from_bits(bits).unwrap();
    //.ok_or(ParserError::Failure(nom::error::ErrorKind::Fail))?;
    Ok((input, flags))
    /*
    map(
        le_u32,
        NegotiateFlags::from_bits,
    )
    */
}

pub fn server_challenge(input: &[u8]) -> IResult<&[u8], ServerChallenge> {
    let (input, slice) = take(8usize)(input)?;
    Ok((input, ServerChallenge::from_slice(slice)))
}

pub fn version(input: &[u8]) -> IResult<&[u8], Version> {
    let (input, major_version) = le_u8(input)?;
    let (input, minor_version) = le_u8(input)?;
    let (input, build_number) = le_u16(input)?;
    let (input, _reserved) = take(3usize)(input)?;
    let (input, ntlm_revision) = le_u8(input)?;
    Ok((
        input,
        Version {
            major_version,
            minor_version,
            build_number,
            ntlm_revision,
        },
    ))
}

pub fn challenge_message(input: &[u8]) -> IResult<&[u8], ChallengeMessage> {
    let (input, _) = tag(ChallengeMessage::SIGNATURE)(input)?;
    let (input, _) = tag(ChallengeMessage::MESSAGE_TYPE.to_le_bytes())(input)?;
    let (input, target_name_len) = le_u16(input)?;
    let (input, _target_name_max_len) = le_u16(input)?;
    let (input, target_name_offset) = le_u32(input)?;
    let (input, negotiate_flags) = negotiate_flags(input)?;
    let (input, server_challenge) = server_challenge(input)?;
    let (input, _reserved) = take(8usize)(input)?;
    let (input, target_info_len) = le_u16(input)?;
    let (input, _target_info_max_len) = le_u16(input)?;
    let (input, target_info_offset) = le_u32(input)?;
    let (input, version) = version(input)?;
    let (input, payload) = rest(input)?;
    // let target_name = peek(
    //     preceded(
    //         take(target_name_offset-ChallengeMessage::PAYLOAD_OFFSET),
    //         take(target_name_len),
    //     )
    // )(payload)?;
    let (_, target_name) = payload_value(
        target_name_offset as usize - ChallengeMessage::PAYLOAD_OFFSET as usize,
        target_name_len as usize,
    )(payload)?;
    // let target_name = unicode_decode(target_name)?;
    let (_, target_info) = payload_value(
        target_info_offset as usize - ChallengeMessage::PAYLOAD_OFFSET as usize,
        target_info_len as usize,
    )(payload)?;
    Ok((
        input,
        ChallengeMessage {
            //target_name,
            target_name: "".to_string(),
            //target_info,
            target_info: AvPairs::empty(),
            negotiate_flags,
            server_challenge,
            version,
        },
    ))
}

fn authenticate_message(input: &[u8]) -> IResult<&[u8], AuthenticateMessage> {
    let (input, _) = tag(AuthenticateMessage::SIGNATURE)(input)?;
    let (input, _) = tag(AuthenticateMessage::MESSAGE_TYPE.to_le_bytes())(input)?;
    let (input, lm_challenge_response_fields) = payload_fields(input)?;
    let (input, nt_challenge_response_fields) = payload_fields(input)?;
    let (input, domain_name_fields) = payload_fields(input)?;
    let (input, user_name_fields) = payload_fields(input)?;
    let (input, workstation_fields) = payload_fields(input)?;
    let (input, encrypted_random_session_key_fields) = payload_fields(input)?;
    let (input, negotiate_flags) = negotiate_flags(input)?;
    let (input, version) = version(input)?;
    let (input, mic) = mic(input)?;
    let (input, payload) = rest(input)?;
    todo!()
}

fn payload_fields(input: &[u8]) -> IResult<&[u8], PayloadFields> {
    map(tuple((le_u16, le_u16, le_u32)), |(len, max_len, offset)| {
        PayloadFields {
            len,
            max_len,
            offset,
        }
    })(input)
}

fn payload_value(offset: usize, length: usize) -> impl FnMut(&[u8]) -> IResult<&[u8], &[u8]> {
    move |i| peek(preceded(take(offset), take(length)))(i)
}

fn mic(input: &[u8]) -> IResult<&[u8], Mic> {
    map(take(16usize), |src: &[u8]| {
        let mut inner = [0u8; 16];
        inner.copy_from_slice(src);
        Mic { inner }
    })(input)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    // 4.2.1 Common Values
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7fc694c9-397a-446a-bd80-4635000f2c0f
    const SERVER_CHALLENGE: &'static [u8] = &hex!("01 23 45 67 89 ab cd ef");

    // 4.2.4.3 Messages
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bc612491-fb0b-4829-91bc-7c6b95ff67fe
    const CHALLENGE_MESSAGE: &[u8] = &hex!(
        "4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00"
        "38 00 00 00 33 82 8a e2 01 23 45 67 89 ab cd ef"
        "00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00"
        "06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00"
        "65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00"
        "69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00"
        "65 00 72 00 00 00 00 00"
    );
    const AUTHENTICATE_MESSAGE: &[u8] = &hex!(
        "4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00"
        "6c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 00"
        "48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00"
        "5c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e2"
        "05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00"
        "69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00"
        "4d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97"
        "ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa"
        "aa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b"
        "eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00"
        "02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00"
        "01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00"
        "00 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 90"
        "94 ce 1c e9 0b c9 d0 3e"
    );

    #[test]
    fn parse_challenge_message() {
        let (remainder, msg) = challenge_message(CHALLENGE_MESSAGE).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(
            msg.server_challenge,
            ServerChallenge::from_slice(SERVER_CHALLENGE)
        );
        assert_eq!(msg.version, Version::new(6, 0, 6000));
    }

    #[test]
    fn parse_authenticate_message() {
        let (remainder, msg) = authenticate_message(AUTHENTICATE_MESSAGE).unwrap();
        assert_eq!(remainder.len(), 0);
        todo!()
    }
}
