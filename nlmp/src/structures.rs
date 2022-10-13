use bitflags::bitflags;
use bytes::{Bytes, BytesMut};
use nttime::NTTime;

use crate::{unicode, unicode_bytes};

/// 2.2.2.1 AV_PAIR
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e>
#[derive(Clone, Debug)]
pub enum AvPair {
    MsvAvEOL,
    MsvAvNbComputerName(String),
    MsvAvNbDomainName(String),
    MsvAvDnsComputerName(String),
    MsvAvDnsDomainName(String),
    MsvAvDnsTreeName(String),
    MsvAvFlags(u32),
    MsvAvTimestamp(NTTime),
    MsvAvSingleHost,
    MsvAvTargetName(String),
    MsvAvChannelBindings([u8; 16]),
}

impl AvPair {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::MsvAvEOL => vec![0u8; 4],
            Self::MsvAvNbComputerName(computer_name) => {
                let computer_name = unicode(computer_name);
                let mut buf = 1u16.to_le_bytes().to_vec();
                buf.extend((computer_name.len() as u16).to_le_bytes());
                buf.extend(computer_name);
                buf
            }
            Self::MsvAvNbDomainName(domain_name) => {
                let domain_name = unicode(domain_name);
                let mut buf = 2u16.to_le_bytes().to_vec();
                buf.extend((domain_name.len() as u16).to_le_bytes());
                buf.extend(domain_name);
                buf
            }
            Self::MsvAvTimestamp(nt_time) => nt_time.encode().to_vec(),
            _ => todo!(),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::MsvAvEOL => Bytes::from_static(&[0u8; 4]),
            Self::MsvAvNbComputerName(computer_name) => {
                let computer_name = unicode_bytes(computer_name);
                let mut buf = BytesMut::from(1u16.to_le_bytes().as_ref());
                buf.extend_from_slice(&(computer_name.len() as u16).to_le_bytes());
                buf.extend_from_slice(&computer_name);
                buf.freeze()
            }
            Self::MsvAvNbDomainName(domain_name) => {
                let domain_name = unicode_bytes(domain_name);
                let mut buf = BytesMut::from(2u16.to_le_bytes().as_ref());
                buf.extend_from_slice(&(domain_name.len() as u16).to_le_bytes());
                buf.extend_from_slice(&domain_name);
                buf.freeze()
            }
            Self::MsvAvTimestamp(nt_time) => Bytes::copy_from_slice(&nt_time.encode()),
            _ => todo!(),
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum AvId {
    MsvAvEOL = 0x0000,
    MsvAvNbComputerName = 0x0001,
    MsvAvNbDomainName = 0x0002,
    MsvAvDnsComputerName = 0x0003,
    MsvAvDnsDomainName = 0x0004,
    MsvAvDnsTreeName = 0x0005,
    MsvAvFlags = 0x0006,
    MsvAvTimestamp = 0x0007,
    MsvAvSingleHost = 0x0008,
    MsvAvTargetName = 0x0009,
    MsvAvChannelBindings = 0x000a,
}

/// Sequence of AV_PAIR structures
///
/// Note: When AV pairs are specified, MsvAvEOL MUST be the last item specified. All other AV pairs,
/// if present, can be specified in any order.
#[repr(transparent)]
pub struct AvPairs {
    inner: Vec<AvPair>,
}

impl AvPairs {
    pub fn builder() -> AvPairsBuilder {
        AvPairsBuilder { inner: Vec::new() }
    }

    pub fn empty() -> Self {
        Self {
            inner: vec![AvPair::MsvAvEOL],
        }
    }

    pub fn new(domain: String, server: String) -> Self {
        let mut inner = Vec::with_capacity(3);
        inner.push(AvPair::MsvAvNbDomainName(domain));
        inner.push(AvPair::MsvAvNbComputerName(server));
        inner.push(AvPair::MsvAvEOL);
        Self { inner }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for pair in &self.inner {
            buf.extend(pair.to_vec());
        }
        buf
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        for pair in &self.inner {
            buf.extend(pair.to_bytes());
        }
        buf.freeze()
    }
}

pub struct AvPairsBuilder {
    inner: Vec<AvPair>,
}

impl AvPairsBuilder {
    pub fn computer_name(mut self, computer_name: String) -> Self {
        self.inner.push(AvPair::MsvAvNbComputerName(computer_name));
        self
    }

    pub fn domain_name(mut self, domain_name: String) -> Self {
        self.inner.push(AvPair::MsvAvNbDomainName(domain_name));
        self
    }

    pub fn timestamp(mut self, timestamp: NTTime) -> Self {
        self.inner.push(AvPair::MsvAvTimestamp(timestamp));
        self
    }

    pub fn target_name(mut self, target_name: String) -> Self {
        self.inner.push(AvPair::MsvAvTargetName(target_name));
        self
    }

    pub fn build(mut self) -> AvPairs {
        self.inner.push(AvPair::MsvAvEOL);
        AvPairs { inner: self.inner }
    }
}

/// 2.2.2.7 NTLM v2: NTLMv2_CLIENT_CHALLENGE
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b
pub struct Ntlmv2ClientChallenge {
    timestamp: NTTime,
    challenge_from_client: [u8; 8],
    av_pairs: Vec<AvPair>,
}

impl Ntlmv2ClientChallenge {
    const RESPTYPE: u8 = 0x01;
    const HIRESPTYPE: u8 = 0x01;
    const RESERVED1: &'static [u8] = &0x0000u16.to_le_bytes();
    const RESERVED2: &'static [u8] = &0x00000000u32.to_le_bytes();
    const RESERVED3: &'static [u8] = &0x00000000u32.to_le_bytes();

    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.push(Self::RESPTYPE);
        vec.push(Self::HIRESPTYPE);
        vec.extend_from_slice(Self::RESERVED1);
        vec.extend_from_slice(Self::RESERVED2);
        // TimeStamp
        // ChallengeFromClient
        vec.extend_from_slice(Self::RESERVED3);
        // AvPairs
        vec
    }
}

bitflags! {
    /// 2.2.2.5 NEGOTIATE
    ///
    /// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832>
    pub struct NegotiateFlags: u32 {
        const NTLMSSP_NEGOTIATE_56 = 0x80000000;
        const NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000;
        const NTLMSSP_NEGOTIATE_128 = 0x20000000;
        //const NTLMSSP_RESERVED_01 = 0x10000000;
        //const NTLMSSP_RESERVED_02 = 0x08000000;
        //const NTLMSSP_RESERVED_03 = 0x04000000;
        const NTLMSSP_NEGOTIATE_VERSION = 0x02000000;
        //const NTLMSSP_RESERVED_04 = 0x01000000;
        const NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000;
        const NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000;
        //const NTLMSSP_RESERVED_05 = 0x00200000;
        const NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000;
        const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000;
        //const NTLMSSP_RESERVED_06 = 0x00040000;
        const NTLMSSP_TARGET_TYPE_SERVER = 0x00020000;
        const NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000;
        const NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x8000;
        //const NTLMSSP_RESERVED_07 = 0x4000;
        const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x2000;
        const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x1000;
        //const NTLMSSP_J = 0x0800;
        //const NTLMSSP_RESERVED_08 = 0x0400;
        const NTLMSSP_NEGOTIATE_NTLM = 0x0200;
        //const NTLMSSP_RESERVED_09 = 0x0100;
        const NTLMSSP_NEGOTIATE_LM_KEY = 0x0080;
        const NTLMSSP_NEGOTIATE_DATAGRAM = 0x0040;
        const NTLMSSP_NEGOTIATE_SEAL = 0x0020;
        const NTLMSSP_NEGOTIATE_SIGN = 0x0010;
        //const NTLMSSP_RESERVED_10 = 0x0008;
        const NTLMSSP_REQUEST_TARGET = 0x0004;
        const NTLM_NEGOTIATE_OEM = 0x0002;
        const NTLMSSP_NEGOTIATE_UNICODE = 0x0001;
        const DEFAULT =
            Self::NTLMSSP_NEGOTIATE_56.bits |
            Self::NTLMSSP_NEGOTIATE_KEY_EXCH.bits |
            Self::NTLMSSP_NEGOTIATE_128.bits |
            Self::NTLMSSP_NEGOTIATE_VERSION.bits |
            Self::NTLMSSP_NEGOTIATE_IDENTIFY.bits |
            Self::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.bits |
            Self::NTLMSSP_NEGOTIATE_ALWAYS_SIGN.bits |
            //Self::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.bits |
            //Self::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.bits |
            Self::NTLMSSP_NEGOTIATE_NTLM.bits |
            Self::NTLMSSP_NEGOTIATE_LM_KEY.bits |
            Self::NTLMSSP_NEGOTIATE_SEAL.bits |
            Self::NTLMSSP_NEGOTIATE_SIGN.bits |
            Self::NTLMSSP_REQUEST_TARGET.bits |
            Self::NTLM_NEGOTIATE_OEM.bits |
            Self::NTLMSSP_NEGOTIATE_UNICODE.bits;
        const EXAMPLE =
            Self::NTLMSSP_NEGOTIATE_KEY_EXCH.bits |
            Self::NTLMSSP_NEGOTIATE_56.bits |
            Self::NTLMSSP_NEGOTIATE_128.bits |
            Self::NTLMSSP_NEGOTIATE_VERSION.bits |
            Self::NTLMSSP_NEGOTIATE_TARGET_INFO.bits |
            Self::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.bits |
            Self::NTLMSSP_TARGET_TYPE_SERVER.bits |
            Self::NTLMSSP_NEGOTIATE_ALWAYS_SIGN.bits |
            Self::NTLMSSP_NEGOTIATE_NTLM.bits |
            Self::NTLMSSP_NEGOTIATE_SEAL.bits |
            Self::NTLMSSP_NEGOTIATE_SIGN.bits |
            Self::NTLM_NEGOTIATE_OEM.bits |
            Self::NTLMSSP_NEGOTIATE_UNICODE.bits;
    }
}

impl NegotiateFlags {
    pub fn to_vec(&self) -> Vec<u8> {
        self.bits.to_le_bytes().to_vec()
    }
}

/// [MS-NLMP] 2.2.2.10 VERSION
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175>
#[derive(Debug, PartialEq)]
pub struct Version {
    /// ProductMajorVersion (1 byte)
    pub major_version: u8,
    /// ProductMinorVersion (1 byte)
    pub minor_version: u8,
    /// ProductBuild (2 bytes)
    pub build_number: u16,
    /// NTLMRevisionCurrent (1 byte)
    pub ntlm_revision: u8,
}

impl Version {
    pub fn new(major_version: u8, minor_version: u8, build_number: u16) -> Self {
        Self {
            major_version,
            minor_version,
            build_number,
            ntlm_revision: 15,
        }
    }

    pub const fn vista() -> Self {
        Self {
            major_version: 6,
            minor_version: 0,
            build_number: 6000,
            ntlm_revision: 15,
        }
    }

    pub const fn vista_sp1() -> Self {
        Self {
            major_version: 6,
            minor_version: 0,
            build_number: 6001,
            ntlm_revision: 15,
        }
    }

    pub const fn vista_sp2() -> Self {
        Self {
            major_version: 6,
            minor_version: 0,
            build_number: 6002,
            ntlm_revision: 15,
        }
    }

    pub const fn win7() -> Self {
        Self {
            major_version: 6,
            minor_version: 1,
            build_number: 7600,
            ntlm_revision: 15,
        }
    }

    pub const fn win7_sp1() -> Self {
        Self {
            major_version: 6,
            minor_version: 1,
            build_number: 7601,
            ntlm_revision: 15,
        }
    }

    pub const fn win10_1607() -> Self {
        Self {
            major_version: 10,
            minor_version: 0,
            build_number: 14393,
            ntlm_revision: 15,
        }
    }

    pub fn encode(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.major_version;
        buf[1] = self.minor_version;
        [buf[2], buf[3]] = self.build_number.to_le_bytes();
        buf[7] = self.ntlm_revision;
        buf
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.push(self.major_version);
        vec.push(self.minor_version);
        vec.extend(self.build_number.to_le_bytes());
        vec.extend(b"\x00\x00\x00");
        vec.push(self.ntlm_revision);
        vec
    }
}

impl Default for Version {
    fn default() -> Self {
        Self {
            major_version: 10,
            minor_version: 0,
            build_number: 14393,
            ntlm_revision: 15,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use pretty_hex::PrettyHex;

    use super::*;

    #[test]
    fn flags_example_value() {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/125f7a94-933e-4023-a146-a449e49bf774
        let flags: NegotiateFlags = NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH
            | NegotiateFlags::NTLMSSP_NEGOTIATE_56
            | NegotiateFlags::NTLMSSP_NEGOTIATE_128
            | NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION
            | NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO
            | NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NegotiateFlags::NTLMSSP_TARGET_TYPE_SERVER
            | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
            | NegotiateFlags::NTLMSSP_NEGOTIATE_SEAL
            | NegotiateFlags::NTLMSSP_NEGOTIATE_SIGN
            | NegotiateFlags::NTLM_NEGOTIATE_OEM
            | NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;
        assert_eq!(&flags.bits.to_le_bytes(), &[0x33, 0x82, 0x8a, 0xe2])
    }

    #[test]
    fn servername_to_vec_works() {
        let servername = AvPairs::builder()
            .domain_name("Domain".to_string())
            .computer_name("Server".to_string())
            .build();
        let serialized = &servername.to_vec();
        let expected = &hex!(
            "02 00 0c 00  44 00 6f 00  6d 00 61 00  69 00 6e 00"
            "01 00 0c 00  53 00 65 00  72 00 76 00  65 00 72 00"
            "00 00 00 00"
        );
        assert_eq!(
            serialized,
            expected,
            "\n==serialized:==\n{:?}\n==expected:==\n{:?}\n",
            serialized.hex_dump(),
            expected.hex_dump(),
        )
    }
}
