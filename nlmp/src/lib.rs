//! # [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
//!
//! <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4>
//!
//! ## Example
//!
//! First, generate a NEGOTIATE message:
//!
//! ```
//! let ntlm = Ntlm::negotiate("Domain".to_string(), "Workstation".to_string());
//! let negotiate_message = ntlm.negotiate();
//! ```
//!
//! Send the NEGOTIATE message to the target to get a CHALLENGE message in return. Consume the
//! CHALLENGE message to generate an AUTHENTICATE message:
//!
//! ```
//! let authenticate_message = ntlm.authenticate(challenge_message);
//! ```
//!
//! Send the AUTHENTICATE message to the target to complete the negotiation. Then use the `Ntlm`
//! value for signing and sealing (encryption):
//!
//! ```
//! let signed_msg = ntlm.sign(&msg);
//! let sealed_msg = ntlm.sign_and_seal(&msg);
//! ```

mod auth;
mod error;
mod messages;
mod nthash;
pub mod parser;
mod structures;
mod unicode;

pub use auth::ntowfv2;
pub use error::{Error, Result};
pub use messages::{
    AuthenticateMessage, ChallengeMessage, MessageType, NegotiateMessage, ServerChallenge,
};
pub use nthash::NtHash;
pub use structures::{NegotiateFlags, Version};
pub use unicode::{unicode, unicode_bytes};

/// # NTLMv2 Session Context
pub struct Ntlm {
    negotiate: NegotiateMessage,
    challenge: ChallengeMessage,
    authenticate: AuthenticateMessage,
    //session_base_key: [u8; 16],
    //session_key: [u8: 16],
    //sign_key: [u8: 16],
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bf39181d-e95d-40d7-a740-ab4ec3dc363d
    //seal_key: [u8: 16],
}

impl Ntlm {
    pub fn negotiate(domain_name: String, workstation_name: String) -> NtlmClientHandshake {
        NtlmClientHandshake {
            negotiate: NegotiateMessage::new(domain_name, workstation_name),
        }
    }

    pub fn challenge(negotiate: NegotiateMessage) -> NtlmServerHandshake {
        //let challenge = ChallengeMessage {}
        //NtlmServerHandshake { negotiate, challenge }
        todo!()
    }

    pub fn unwrap(&self, data: &[u8]) -> &[u8] {
        todo!()
    }
}

pub struct NtlmClientHandshake {
    negotiate: NegotiateMessage,
}

impl NtlmClientHandshake {
    pub fn authenticate(mut self, message: ChallengeMessage) -> Result<Ntlm> {
        todo!()
    }
}

pub struct NtlmServerHandshake {
    negotiate: NegotiateMessage,
    challenge: ChallengeMessage,
}

impl NtlmServerHandshake {
    pub fn finalize(mut self, message: AuthenticateMessage) -> Result<Ntlm> {
        Ok(Ntlm {
            negotiate: self.negotiate,
            challenge: self.challenge,
            authenticate: message,
        })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use md5::{Digest, Md5};
    use pretty_hex::PrettyHex;
    use rc4::{KeyInit, Rc4, StreamCipher};

    use super::*;

    const NEGOTIATE: &'static [u8] = hex!(
        "4e 54 4c 4d 53 53 50 00 01 00 00 00 b7 82 08 e2"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "0a 00 61 4a 00 00 00 0f"
    )
    .as_slice();

    const CHALLENGE: &'static [u8] = hex!(
        "4e 54 4c 4d 53 53 50 00 02 00 00 00 12 00 12 00"
        "38 00 00 00 35 82 89 e2 73 d7 36 4c b1 a5 cf 35"
        "00 00 00 00 00 00 00 00 9a 00 9a 00 4a 00 00 00"
        "0a 00 39 38 00 00 00 0f 57 00 49 00 4e 00 44 00"
        "4f 00 4d 00 41 00 49 00 4e 00 02 00 12 00 57 00"
        "49 00 4e 00 44 00 4f 00 4d 00 41 00 49 00 4e 00"
        "01 00 04 00 44 00 43 00 04 00 1e 00 77 00 69 00"
        "6e 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 2e 00"
        "6c 00 6f 00 63 00 61 00 6c 00 03 00 24 00 64 00"
        "63 00 2e 00 77 00 69 00 6e 00 64 00 6f 00 6d 00"
        "61 00 69 00 6e 00 2e 00 6c 00 6f 00 63 00 61 00"
        "6c 00 05 00 1e 00 77 00 69 00 6e 00 64 00 6f 00"
        "6d 00 61 00 69 00 6e 00 2e 00 6c 00 6f 00 63 00"
        "61 00 6c 00 07 00 08 00 4c 86 b5 1e 84 a7 d8 01"
        "00 00 00 00"
    )
    .as_slice();

    const AUTHENTICATE: &'static [u8] = hex!(
        "4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00"
        "ae 00 00 00 40 01 40 01 c6 00 00 00 1e 00 1e 00"
        "58 00 00 00 1a 00 1a 00 76 00 00 00 1e 00 1e 00"
        "90 00 00 00 10 00 10 00 06 02 00 00 35 82 88 e2"
        "0a 00 61 4a 00 00 00 0f ef f7 c3 df 4c b7 1c e6"
        "68 48 72 c0 bb 68 ce 26 77 00 69 00 6e 00 64 00"
        "6f 00 6d 00 61 00 69 00 6e 00 2e 00 6c 00 6f 00"
        "63 00 61 00 6c 00 41 00 64 00 6d 00 69 00 6e 00"
        "69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00"
        "44 00 45 00 53 00 4b 00 54 00 4f 00 50 00 2d 00"
        "34 00 4b 00 55 00 45 00 51 00 4b 00 46 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 2f ed 66 5f 65 60 ea ba ef 3e"
        "0e 49 2f 34 7c 21 01 01 00 00 00 00 00 00 4c 86"
        "b5 1e 84 a7 d8 01 78 18 a6 87 ec 48 23 08 00 00"
        "00 00 02 00 12 00 57 00 49 00 4e 00 44 00 4f 00"
        "4d 00 41 00 49 00 4e 00 01 00 04 00 44 00 43 00"
        "04 00 1e 00 77 00 69 00 6e 00 64 00 6f 00 6d 00"
        "61 00 69 00 6e 00 2e 00 6c 00 6f 00 63 00 61 00"
        "6c 00 03 00 24 00 64 00 63 00 2e 00 77 00 69 00"
        "6e 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 2e 00"
        "6c 00 6f 00 63 00 61 00 6c 00 05 00 1e 00 77 00"
        "69 00 6e 00 64 00 6f 00 6d 00 61 00 69 00 6e 00"
        "2e 00 6c 00 6f 00 63 00 61 00 6c 00 07 00 08 00"
        "4c 86 b5 1e 84 a7 d8 01 06 00 04 00 02 00 00 00"
        "08 00 30 00 30 00 00 00 00 00 00 00 01 00 00 00"
        "00 20 00 00 e8 6b 7b 6f d6 20 f4 df 9b f6 b5 0e"
        "03 bb d0 9d ad fe 00 a7 c7 16 c8 10 b1 6f 57 6e"
        "12 e0 55 ac 0a 00 10 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 09 00 22 00 6c 00 64 00"
        "61 00 70 00 2f 00 33 00 2e 00 38 00 32 00 2e 00"
        "31 00 35 00 34 00 2e 00 32 00 30 00 37 00 00 00"
        "00 00 00 00 00 00 2c 64 22 73 71 bd 11 09 53 6e"
        "bf 80 1d 40 b5 03"
    )
    .as_slice();

    #[test]
    fn calculate() {
        todo!()
    }

    #[test]
    fn ntlmssp_seal() {
        let mut data = hex!(
            //"01 00 00 00"
            //"d9 a0 61 83 5d 29 cc a0 00 00 00 00"
            "c4"
        ).to_vec();
        let mut data2 = hex!(
            //"01 00 00 00" // protocol version
            //"a5 cf d9 c5 32 58 62 d2 01 00 00 00" // signature + sequence number
            "9a 86 d9 db c1 31 e7 97"
            "e4 ec d4 3c 37 13 3f 4d"
            "c4 73 e7 95 c0 56 0c bb bb e5 b3 d0 d7 f5 39 fb"
            "5a 45 7c 93 e9 c5 73 a9 a4 4a 9b 75 cd 87 5e 0d"
            "35 a0 ee 8e ce bf 02 ec 7e 0a c7 a2 43 6a ec 56"
            "b7 b9 6b 24 89 89 4c a2 e1 86 6a f2 4f 38 c5 60"
            "e1 70 83 11 7d d5 be 1b df b2 48 1b b1 6f 69 c8"
            "b7 5c f6 f0 a7 a0 87 3f d5 e6 a4 78 13 7d f0 69"
            "6e 0b ac 97 76 91 68 25 aa c1 eb b9 ca 17 75 e6"
            "28 c3 4f b0 f9 27 21 60 b9 06 9b a6 82 b9 ae 59"
            "ad a5 07 24 93 88 ec 17 2c 20 01 2d 16 eb 3d d2"
            "88 5d 74 f8 75 39 63 fe a3 35 4a a5 38 87 2c f3"
            "ec ae a3 80 8f cf a0 e3 09 ca 49 b6 64 be 8d 75"
            "20 b5 54 d8 4a 7e 15 ca 63 7c 80 55 df 77 7a 97"
            "c2 2a b1 20 fd 4b 99 e8 f1 82 fa a7 f1 db 15 1e"
            "11 04 19 d5 24 f9 87 9c 32 bf a7 f9 5a 62 43 1f"
            "7f e4 50 37 97 f1 68 66 5e c4 a9 69 68 42 75 97"
            "2d cf ce 53 5a 6e dc ab bd 3c d4 b0 5a 36 46 a0"
            "c2 6c f6 09 9c 25 56 e5 70 01 9a 31 ac db fa 80"
            "c1 54 e7 43 f0 9f 55 ba 40 13 59 ef cf 58 18 f9"
            "ec 0f 17 e9 91 3f 62 25 41 3d 2c 9f 6f 04 c4 06"
            "b4 99 d1 b2 fe f5 0c 97 3c 1d 0d 74 dd bd 8d d8"
            "96 d8 d9 fb 42 79 c2 c9 e3 66 6a fe 52 dc 26 7b"
            "28 53 a1 08 48 39 8e 61 26 09 cf 8c 23 07 a0 04"
            "03 79 f9 d4 80 4b 13 87 38 f3 72 84 b3 59 63 43"
            "cd 2a 34 36 e3 89 ff ba 9a 2f e7 9e 19 e4 d3 0d"
            "6a 05 14 5e 6a a7 f2 ab f7 4b 57 ca 31 3d 86 c6"
            "cf 86 0f cc 41 e3 cc 9f be 35 06 35 34 e5 a7 11"
            "92 cd b7 97 70 7c 13 6f 27 5a f8 cd 67 1b aa 15"
            "e0 9d 40 32 9d bc da 56 85 10 49 d5 4e cc 2a ab"
            "4b 6b 2f 40 87 c1 0f 35 ba b9 96 3b e2 7f"
        )
        .to_vec();
        //let mut data = hex!("cf0eb0a93901000000884b14809e53bfe700000000").to_vec();
        // let mut data = hex!(
        //     "cf0eb0a939"
        //     //"01000000884b14809e53bfe700000000"
        // )
        // .to_vec();
        let session_key = hex!("a3a72620602e03ad834225f85a4cd5ef");
        //let session_key = hex!("0102030405060708090a0b0c0d0e0f00");
        let mut hasher = Md5::new();
        hasher.update(&session_key);
        hasher.update(b"session key to client-to-server sealing key magic constant\0");
        let sealing_key = hasher.finalize();
        //assert_eq!(sealing_key[..], hex!("6f0d99535033951cbe499cd1914fe9ee"));
        let mut rc4 = Rc4::new(&sealing_key.into());
        rc4.apply_keystream(&mut data);
        println!("{:#?}", data.hex_dump());
        rc4.apply_keystream(&mut b"AAAAAAAA".to_vec());
        rc4.apply_keystream(&mut data2);
        println!("{:#?}", data2.hex_dump());
        todo!()
    }
}
