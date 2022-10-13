use core::time;

/// [MS-NLMP] 3.3.2 NTLM v2 Authentication
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3>
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use nttime::NTTime;

use crate::{structures::AvPairs, unicode, NegotiateFlags, ServerChallenge};

type HmacMd5 = Hmac<Md5>;

const RESPONSEVERSION: u8 = 1;
const HI_RESPONSEVERSION: u8 = 1;

/// NTOWFv2
///
/// Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
/// MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User),
/// UserDom ) ) )
/// EndDefine
pub fn ntowfv2(password: &str, username: &str, userdomain: &str) -> Vec<u8> {
    let key = Md4::new().chain_update(unicode(password)).finalize();
    let msg = unicode(&(username.to_uppercase() + userdomain));
    HmacMd5::new_from_slice(&key)
        .unwrap()
        .chain_update(&msg)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// NTLM v2 ComputeResponse
///
/// Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM,
/// CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName)
/// As
/// If (User is set to "" && Passwd is set to "")
///     -- Special case for anonymous authentication
///     Set NtChallengeResponseLen to 0
///     Set NtChallengeResponseMaxLen to 0
///     Set NtChallengeResponseBufferOffset to 0
///     Set LmChallengeResponse to Z(1)
/// Else
///     Set temp to ConcatenationOf(Responserversion, HiResponserversion,
///     Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
///     Set NTProofStr to HMAC_MD5(ResponseKeyNT,
///     ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
///     Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
///     Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
///     ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
///     ClientChallenge )
/// EndIf
// pub fn compute_response(
//     negotiate_flags: NegotiateFlags,
//     response_key_nt: &[u8],
//     response_key_lm: &[u8],
//     server_challenge: ServerChallenge,
//     client_challenge: Vec<u8>,
//     time: &NTTime,
//     server_name: &AvPairs,
// ) -> Vec<u8> {
//     let mut temp = vec![RESPONSEVERSION, HI_RESPONSEVERSION, 0, 0, 0, 0, 0, 0];
//     temp.extend(time.encode());
//     temp.extend_from_slice(&client_challenge);
//     temp.extend_from_slice(b"\x00\x00\x00\x00");
//     temp.extend(server_name.to_vec());
//     temp.extend_from_slice(b"\x00\x00\x00\x00");
//     let nt_proof_str = HmacMd5::new_from_slice(response_key_nt)
//         .unwrap()
//         .chain_update(&server_challenge.as_slice())
//         .chain_update(&temp)
//         .finalize()
//         .into_bytes();
//     let mut nt_challenge_response = Vec::from(nt_proof_str.as_slice());
//     nt_challenge_response.extend_from_slice(&temp);
//     let mut lm_challenge_response = Vec::from(
//         HmacMd5::new_from_slice(response_key_lm)
//             .unwrap()
//             .chain_update(server_challenge.as_slice())
//             .chain_update(&client_challenge)
//             .finalize()
//             .into_bytes()
//             .as_slice(),
//     );
//     lm_challenge_response.extend_from_slice(&client_challenge);
//     let session_base_key = HmacMd5::new_from_slice(response_key_nt)
//         .unwrap()
//         .chain_update(nt_proof_str.as_slice())
//         .finalize()
//         .into_bytes()
//         .to_vec();
//     session_base_key
// }

pub struct NtlmV2Auth {
    nt_challenge_response: Vec<u8>,
    lm_challenge_response: Vec<u8>,
    session_base_key: Vec<u8>,
}

impl NtlmV2Auth {
    pub fn compute_response(
        negotiate_flags: NegotiateFlags,
        response_key_nt: &[u8],
        response_key_lm: &[u8],
        server_challenge: ServerChallenge,
        client_challenge: Vec<u8>,
        time: &NTTime,
        server_name: &AvPairs,
    ) -> Self {
        let mut temp = vec![RESPONSEVERSION, HI_RESPONSEVERSION, 0, 0, 0, 0, 0, 0];
        temp.extend(time.encode());
        temp.extend_from_slice(&client_challenge);
        temp.extend_from_slice(b"\x00\x00\x00\x00");
        temp.extend(server_name.to_vec());
        temp.extend_from_slice(b"\x00\x00\x00\x00");
        let nt_proof_str = HmacMd5::new_from_slice(response_key_nt)
            .unwrap()
            .chain_update(&server_challenge.as_slice())
            .chain_update(&temp)
            .finalize()
            .into_bytes();
        let mut nt_challenge_response = Vec::from(nt_proof_str.as_slice());
        nt_challenge_response.extend_from_slice(&temp);
        let mut lm_challenge_response = Vec::from(
            HmacMd5::new_from_slice(response_key_lm)
                .unwrap()
                .chain_update(server_challenge.as_slice())
                .chain_update(&client_challenge)
                .finalize()
                .into_bytes()
                .as_slice(),
        );
        lm_challenge_response.extend_from_slice(&client_challenge);
        let session_base_key = HmacMd5::new_from_slice(response_key_nt)
            .unwrap()
            .chain_update(nt_proof_str.as_slice())
            .finalize()
            .into_bytes()
            .to_vec();
        Self {
            nt_challenge_response,
            lm_challenge_response,
            session_base_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use pretty_hex::*;

    use crate::structures::AvPair;

    use super::*;

    // 4.2.1 Common Values
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7fc694c9-397a-446a-bd80-4635000f2c0f
    const USER_DOM: &'static str = "Domain";
    const SERVER_NAME: &'static str = "Server";
    const CLIENT_CHALLENGE: &'static [u8] = &hex!("aa aa aa aa aa aa aa aa");
    const SERVER_CHALLENGE: &'static [u8] = &hex!("01 23 45 67 89 ab cd ef");

    // 4.2.4.1.1 NTOWFv2() and LMOWFv2()
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
    const RESPONSE_KEY_NT: &'static [u8] = &hex!("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f");
    const RESPONSE_KEY_LM: &'static [u8] = RESPONSE_KEY_NT;

    #[test]
    fn md4_works() {
        assert_eq!(
            Md4::new().chain_update(unicode("test")).finalize().to_vec(),
            hex!("0cb6948805f797bf2a82807973b89537").to_vec()
        );
    }

    #[test]
    fn hmac_md5_works() {
        // https://sandbox.ietf.org/doc/html/rfc2202#section-2
        assert_eq!(
            HmacMd5::new_from_slice(&hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
                .unwrap()
                .chain_update("Hi There")
                .finalize()
                .into_bytes()
                .as_slice(),
            &hex!("9294727a3638bb1c13f48ef8158bfc9d")
        )
    }

    #[test]
    fn ntowf2_works() {
        // 4.2.4.1.1 NTOWFv2() and LMOWFv2()
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
        assert_eq!(
            ntowfv2("Password", "User", "Domain"),
            hex!("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f")
        )
        // assert_eq!(
        //     ntowfv2("test", "test", "WORKGROUP"),
        //     hex!("f31eb9f73fc9d5405f9ae516fb068315")
        // )
    }

    // #[test]
    // fn compute_response_works() {
    //     // 4.2.4.1.2 Session Base Key
    //     // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/54973495-20d2-49e8-9925-c399a403ed4a
    //     let computed = compute_response(
    //         NegotiateFlags::DEFAULT,
    //         RESPONSE_KEY_NT,
    //         RESPONSE_KEY_LM,
    //         ServerChallenge::from_slice(SERVER_CHALLENGE),
    //         Vec::from(CLIENT_CHALLENGE),
    //         &NTTime::from(0),
    //         &AvPairs::new(USER_DOM.to_string(), SERVER_NAME.to_string()),
    //     );
    //     let expected = hex!("8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3");
    //     assert_eq!(
    //         computed,
    //         expected,
    //         "\n==computed:==\n{:?}\n==expected:==\n{:?}\n",
    //         computed.hex_dump(),
    //         expected.hex_dump(),
    //     )
    // }

    #[test]
    fn ntlmv2_auth_works() {
        let computed = NtlmV2Auth::compute_response(
            NegotiateFlags::DEFAULT,
            RESPONSE_KEY_NT,
            RESPONSE_KEY_LM,
            ServerChallenge::from_slice(SERVER_CHALLENGE),
            Vec::from(CLIENT_CHALLENGE),
            &NTTime::from(0),
            &AvPairs::new(USER_DOM.to_string(), SERVER_NAME.to_string()),
        );

        // 4.2.4.1.2 Session Base Key
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/54973495-20d2-49e8-9925-c399a403ed4a
        let expected = hex!("8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3");
        assert_eq!(
            computed.session_base_key,
            expected,
            "\n==computed:==\n{:?}\n==expected:==\n{:?}\n",
            computed.session_base_key.hex_dump(),
            expected.hex_dump(),
        );

        // 4.2.4.2.1 LMv2 Response
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7e2b35f9-fe90-49fb-8c9d-30639a899160
        let expected = hex!(
            "86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19"
            "aa aa aa aa aa aa aa aa"
        );
        assert_eq!(
            computed.lm_challenge_response,
            expected,
            "\n==computed:==\n{:?}\n==expected:==\n{:?}\n",
            computed.lm_challenge_response.hex_dump(),
            expected.hex_dump(),
        );

        // 4.2.4.2.2 NTLMv2 Response
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/fa2bc0f0-9efa-40d7-a165-adfccd7f6da7
        // 
        // 4.2.4.1.3 temp
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/946f54bd-76b5-4b18-ace8-6e8c992d5847
        let expected = hex!(
            "68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c"

            "01 01 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00"
            "02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00"
            "01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00"
            "00 00 00 00 00 00 00 00"
        );
        assert_eq!(
            computed.nt_challenge_response,
            expected,
            "\n==computed:==\n{:?}\n==expected:==\n{:?}\n",
            computed.nt_challenge_response.hex_dump(),
            expected.hex_dump(),
        );
    }
}
