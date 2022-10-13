use std::convert::TryInto;

use crate::{
    auth::NtlmV2Auth,
    structures::{AvPairs, NegotiateFlags, Version},
    unicode,
};

#[repr(u32)]
pub enum MessageType {
    Negotiate = 0x00000001,
    Challenge = 0x00000002,
    Authenticate = 0x00000003,
}

/// 2.2.1.1 NEGOTIATE_MESSAGE
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2>
pub struct NegotiateMessage {
    pub negotiate_flags: NegotiateFlags,
    pub domain_name: String,      // TODO: OEM string?
    pub workstation_name: String, // TODO: OEM string?
    pub version: Version,
}

impl NegotiateMessage {
    pub const SIGNATURE: &'static [u8] = b"NTLMSSP\x00";
    pub const MESSAGE_TYPE: u32 = 0x00000001;
    pub const PAYLOAD_OFFSET: u32 = 40;

    pub fn new(domain_name: String, workstation_name: String) -> Self {
        Self {
            negotiate_flags: NegotiateFlags::DEFAULT,
            domain_name,
            workstation_name,
            version: Version::default(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(Self::SIGNATURE);
        vec.extend(Self::MESSAGE_TYPE.to_le_bytes());
        vec.extend(self.negotiate_flags.to_vec());
        let domain_name_len: u16 = self
            .domain_name
            .len()
            .try_into()
            .expect("DomainName field cannot be larger than u16 capacity");
        let workstation_len: u16 = self
            .workstation_name
            .len()
            .try_into()
            .expect("WorkstationName field cannot be larger than u16 capacity");
        let domain_name_offset: u32 = Self::PAYLOAD_OFFSET;
        let workstation_offset: u32 = domain_name_offset + (workstation_len as u32);
        vec.extend(domain_name_len.to_le_bytes()); // DomainNameLen
        vec.extend(domain_name_len.to_le_bytes()); // DomainNameMaxLen
        vec.extend(domain_name_offset.to_le_bytes()); // DomainNameBufferOffset
        vec.extend(workstation_len.to_le_bytes()); // WorkstationLen
        vec.extend(workstation_len.to_le_bytes()); // WorkstationMaxLen
        vec.extend(workstation_offset.to_le_bytes()); // WorkstationBufferOffset
        vec.extend(self.version.to_vec());
        vec.extend_from_slice(self.domain_name.as_bytes()); // TODO: OEM string?
        vec.extend_from_slice(self.workstation_name.as_bytes()); // TODO: OEM string?
        vec
    }
}

/// 2.2.1.2 CHALLENGE_MESSAGE
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786>
pub struct ChallengeMessage {
    pub(crate) target_name: String, // TODO: OEM string?
    pub(crate) target_info: AvPairs,
    pub(crate) negotiate_flags: NegotiateFlags,
    pub(crate) server_challenge: ServerChallenge,
    pub(crate) version: Version,
}

// Redo ChallengeMessage with raw payload
// pub struct ChallengeMessage2 {
//     pub(crate) target_name_fields: PayloadFields,
//     pub(crate) target_info_fields: PayloadFields,
//     pub(crate) negotiate_flags: NegotiateFlags,
//     pub(crate) server_challenge: ServerChallenge,
//     pub(crate) version: Version,
//     pub(crate) payload: Vec<u8>,
// }

impl ChallengeMessage {
    pub const SIGNATURE: &'static [u8] = b"NTLMSSP\x00";
    pub const MESSAGE_TYPE: u32 = 0x00000002;
    pub const PAYLOAD_OFFSET: u32 = 56;

    pub fn to_vec(&self) -> Vec<u8> {
        let target_info_bytes = self.target_info.to_vec();
        let mut vec = Vec::new(); // TODO: with_capacity()
        vec.extend_from_slice(Self::SIGNATURE);
        vec.extend(Self::MESSAGE_TYPE.to_le_bytes());
        let target_name = unicode(&self.target_name);
        let target_name_len: u16 = target_name
            .len()
            .try_into()
            .expect("TargetName field cannot be larger than u16::MAX");
        let target_name_offset: u32 = Self::PAYLOAD_OFFSET;
        vec.extend(target_name_len.to_le_bytes()); // TargetNameLen
        vec.extend(target_name_len.to_le_bytes()); // TargetNameMaxLen
        vec.extend(target_name_offset.to_le_bytes()); // TargetNameBufferOffset
        vec.extend(self.negotiate_flags.to_vec());
        vec.extend_from_slice(&self.server_challenge.bytes);
        vec.extend_from_slice(&[0; 8]); // Reserved (8 bytes)
        let target_info_len: u16 = target_info_bytes
            .len()
            .try_into()
            .expect("TargetInfo field cannot be larger than u16::MAX");
        let target_info_offset: u32 = target_name_offset + (target_name_len as u32);
        vec.extend(target_info_len.to_le_bytes()); // TargetInfoLen
        vec.extend(target_info_len.to_le_bytes()); // TargetInfoMaxLen
        vec.extend(target_info_offset.to_le_bytes()); // TargetInfoBufferOffset
        vec.extend(self.version.to_vec());
        vec.extend_from_slice(&target_name); // TODO: OEM string?
        vec.extend(target_info_bytes);
        vec
    }
}

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct ServerChallenge {
    bytes: [u8; 8],
}

impl ServerChallenge {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self { bytes }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(slice);
        Self { bytes }
    }
}

/// 2.2.1.3 AUTHENTICATE_MESSAGE
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce>
pub struct AuthenticateMessage {
    lm_challenge_response: Vec<u8>,
    nt_challenge_response: Vec<u8>,
    domain_name: String,
    user_name: String,
    workstation: String, // TODO: OEM string?
    encrypted_random_session_key: Vec<u8>,
    negotiate_flags: NegotiateFlags,
    version: Version,
    mic: Mic,
}

impl AuthenticateMessage {
    pub const SIGNATURE: &'static [u8] = b"NTLMSSP\0";
    pub const MESSAGE_TYPE: u32 = 0x00000003;

    pub fn generate(
        challenge: ServerChallenge,
        domain_name: String,
        user_name: String,
        workstation: String,
    ) -> Self {
        todo!()
        /*
        Self {
            lm_challenge_response: (),
            nt_challenge_response: (),
            domain_name: (),
            user_name: (),
            workstation: (),
            encrypted_random_session_field: (),
            negotiate_flags: (),
            version: (),
            mic: (),
        }
        */
    }
}

pub struct PayloadFields {
    len: u16,
    max_len: u16,
    buffer_offset: u32,
}

pub struct Mic {
    pub(crate) inner: [u8; 16],
}

impl Mic {
    /// 3.1.5.1.2 Client Receives a CHALLENGE_MESSAGE from the Server
    ///
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96
    fn new(
        session_key: NtlmV2Auth,
        negotiate: NegotiateMessage,
        challenge: ChallengeMessage,
        authenticate: AuthenticateMessage,
    ) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use pretty_hex::PrettyHex;

    use crate::{structures::AvPairs, unicode};

    use super::*;

    // 4.2.1 Common Values
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7fc694c9-397a-446a-bd80-4635000f2c0f
    const SERVER_CHALLENGE: &'static [u8] = &hex!("01 23 45 67 89 ab cd ef");

    // 4.2.4.3 Messages
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bc612491-fb0b-4829-91bc-7c6b95ff67fe
    const CHALLENGE_MESSAGE: &'static [u8] = &hex!(
        "4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00"
        "38 00 00 00 33 82 8a e2 01 23 45 67 89 ab cd ef"
        "00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00"
        "06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00"
        "65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00"
        "69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00"
        "65 00 72 00 00 00 00 00"
    );

    const AUTHENTICATE_MESSAGE: &'static [u8] = &hex!(
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
    fn negotiate_message_to_vec() {
        let msg = NegotiateMessage {
            negotiate_flags: NegotiateFlags::DEFAULT,
            domain_name: "".to_string(),
            workstation_name: "".to_string(),
            version: Default::default(),
        };
        let expected = b"NTLMSSP\x00\
            \x01\x00\x00\x00\
            \xb7\x82\x18\xe2\
            \x00\x00\
            \x00\x00\
            \x28\x00\x00\x00\
            \x00\x00\
            \x00\x00\
            \x28\x00\x00\x00\
            \x0a\x00\x39\x38\x00\x00\x00\x0f"
            .to_vec();
        assert_eq!(expected, msg.to_vec());
    }

    #[test]
    fn challenge_message_to_vec() {
        let msg = ChallengeMessage {
            target_name: "".into(),
            target_info: AvPairs::empty(),
            negotiate_flags: NegotiateFlags::DEFAULT,
            server_challenge: ServerChallenge {
                bytes: b"\x66\xe8\x42\xc9\x4d\x59\x6a\xc8".clone(),
            },
            version: Default::default(),
        };
        let expected = b"NTLMSSP\x00\
            \x02\x00\x00\x00\
            \x00\x00\
            \x00\x00\
            \x38\x00\x00\x00\
            \xb7\x82\x18\xe2\
            \x66\xe8\x42\xc9\x4d\x59\x6a\xc8\
            \x00\x00\x00\x00\x00\x00\x00\x00\
            \x04\x00\
            \x04\x00\
            \x38\x00\x00\x00\
            \x0a\x00\x39\x38\x00\x00\x00\x0f\
            \x00\x00\x00\x00"
            .to_vec();
        assert_eq!(expected, msg.to_vec());
        let msg = ChallengeMessage {
            target_name: "Server".into(),
            target_info: AvPairs::new("Domain".into(), "Server".into()),
            negotiate_flags: NegotiateFlags::EXAMPLE,
            server_challenge: ServerChallenge::from_slice(SERVER_CHALLENGE),
            version: Version::new(6, 0, 6000),
        };
        let serialized = &msg.to_vec();
        let expected = CHALLENGE_MESSAGE;
        assert_eq!(
            serialized,
            expected,
            "\n==serialized:==\n{:?}\n==expected:==\n{:?}\n",
            serialized.hex_dump(),
            expected.hex_dump(),
        )
    }
}
