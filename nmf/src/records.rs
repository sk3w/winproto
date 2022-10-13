extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

pub trait Record {
    const RECORD_TYPE: u8;

    //fn to_wire(&self) -> &[u8];
}

#[repr(u8)]
pub enum RecordType {
    VersionRecord = 0x00,
    ModeRecord = 0x01,
    ViaRecord = 0x02,
    KnownEncodingRecord = 0x03,
    ExtensibleEncodingRecord = 0x04,
    UnsizedEnvelopeRecord = 0x05,
    SizedEnvelopeRecord = 0x06,
    EndRecord = 0x07,
    FaultRecord = 0x08,
    UpgradeRequestRecord = 0x09,
    UpgradeResponseRecord = 0x0A,
    PreambleAckRecord = 0x0B,
    PreambleEndRecord = 0x0C,
}

pub fn encode_record_size(size: usize) -> Vec<u8> {
    match size {
        0..=0x7f => vec![size as u8 & 0x7f],
        0x80..=0x3fff => vec![size as u8 & 0x7f | 0x80, (size >> 7) as u8 & 0x7f],
        0x4000..=0x1f_ffff => vec![
            size as u8 & 0x7f | 0x80,
            (size >> 7) as u8 & 0x7f | 0x80,
            (size >> 14) as u8 & 0x7f,
        ],
        0x20_0000..=0x0fff_ffff => vec![
            size as u8 & 0x7f | 0x80,
            (size >> 7) as u8 & 0x7f | 0x80,
            (size >> 14) as u8 & 0x7f | 0x80,
            (size >> 21) as u8 & 0x7f,
        ],
        0x1000_0000..=0x7fff_ffff => vec![
            size as u8 & 0x7f | 0x80,
            (size >> 7) as u8 & 0x7f | 0x80,
            (size >> 14) as u8 & 0x7f | 0x80,
            (size >> 21) as u8 & 0x7f | 0x80,
            (size >> 28) as u8 & 0x7f,
        ],
        _ => panic!("size too large"),
    }
}

/// # MC-NMF 2.2.3.1 Version Record
///
/// The Version Record is a Property Record used to indicate which version of the .NET Message
/// Framing Protocol is being used. Only `MajorVersion=1,MinorVersion=0` is valid.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/b8dfbcd6-b65b-495a-a1f1-e19b78897a3d>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VersionRecord;

impl Record for VersionRecord {
    const RECORD_TYPE: u8 = RecordType::VersionRecord as u8;
}

impl VersionRecord {
    pub const MAJOR_VERSION: u8 = 0x01;
    pub const MINOR_VERSION: u8 = 0x00;
}

/// # MC-NMF 2.2.3.2 Mode Record
///
/// The Mode Record is a Property Record that defines the communication mode for the session.
/// The default value is `Duplex`.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/8cd0b687-a7fc-45e5-b328-e00225836af3>
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum ModeRecord {
    SingletonUnsized = 0x01,
    Duplex = 0x02,
    Simplex = 0x03,
    SingletonSized = 0x04,
}

impl Default for ModeRecord {
    fn default() -> Self {
        Self::Duplex
    }
}

impl Record for ModeRecord {
    const RECORD_TYPE: u8 = RecordType::ModeRecord as u8;
}

/// # MC-NMF 2.2.3.3 Via Record
///
/// The Via Record is a Property Record that defines the URI for which subsequent messages are bound.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/2d61448a-b4d1-4cbd-911c-d5caff54b64f>
#[derive(Debug, PartialEq)]
pub struct ViaRecord(String);

impl ViaRecord {
    pub fn new<S: Into<String>>(uri: S) -> Self {
        Self(uri.into())
    }

    pub fn from_utf8(v: &[u8]) -> Result<Self, core::str::Utf8Error> {
        let s = core::str::from_utf8(v)?;
        Ok(Self(s.to_string()))
    }

    pub fn inner_bytes(&self) -> &[u8] {
        let Self(uri) = self;
        uri.as_bytes()
    }
}

impl Record for ViaRecord {
    const RECORD_TYPE: u8 = RecordType::ViaRecord as u8;
}

/// # MC-NMF 2.2.3.4.1 Known Encoding Record
///
/// The Known Encoding Record indicates a previously known encoding for the subsequent Envelope Records.
/// The default value is `Soap12Nbfse`.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/a7d44463-2c60-482d-8856-9a8ff5929c62>
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum KnownEncodingRecord {
    Soap11Utf8 = 0x00,
    Soap11Utf16 = 0x01,
    Soap11UnicodeLE = 0x02,
    Soap12Utf8 = 0x03,
    Soap12Utf16 = 0x04,
    Soap12UnicodeLE = 0x05,
    Soap12Mtom = 0x06,
    Soap12Nbfs = 0x07,
    Soap12Nbfse = 0x08,
}

impl Default for KnownEncodingRecord {
    fn default() -> Self {
        Self::Soap12Nbfse
    }
}

impl Record for KnownEncodingRecord {
    const RECORD_TYPE: u8 = RecordType::KnownEncodingRecord as u8;
}

/// # MC-NMF 2.2.3.4.2 Extensible Encoding Record
///
/// The Extensible Encoding Record indicates an ad hoc encoding for subsequent Envelope Records.
/// The record data in this case is a Multipurpose Internet Mail Extensions (MIME) content type,
/// as specified in RFC2045, which is encoded by using UTF-8 encoding.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/ac28de93-1842-4d66-8074-1c2a34e24720>
#[derive(Debug, PartialEq)]
pub struct ExtensibleEncodingRecord {
    // TODO: implement MIME content-type, subtype, and parameters
    pub(crate) payload: Vec<u8>,
}

impl Record for ExtensibleEncodingRecord {
    const RECORD_TYPE: u8 = RecordType::ExtensibleEncodingRecord as u8;
}

/// # MC-NMF 2.2.3.5 Upgrade Request Record
///
/// The Upgrade Request Record is a Property Record that requests a protocol upgrade.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/6ef3ede8-2ead-42ce-abf1-6d144271746f>
///
/// NOTE: WCF on Windows only supports "application/negotiate" and "application/ssl-tls" per
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/a9856ce3-3001-46f4-aac3-9e7b5b9d736c#Appendix_A_6>
#[derive(Debug, PartialEq)]
pub struct UpgradeRequestRecord(String);

impl Record for UpgradeRequestRecord {
    const RECORD_TYPE: u8 = RecordType::UpgradeRequestRecord as u8;
}

impl UpgradeRequestRecord {
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    pub fn from_utf8(v: &[u8]) -> Result<Self, core::str::Utf8Error> {
        let s = core::str::from_utf8(v)?;
        Ok(Self(s.to_string()))
    }

    pub fn negotiate() -> Self {
        Self("application/negotiate".into())
    }

    pub fn ssl_tls() -> Self {
        Self("application/ssl-tls".into())
    }

    pub fn inner_bytes(&self) -> &[u8] {
        let Self(inner) = self;
        inner.as_bytes()
    }
}

/// MC-NMF 2.2.3.6 Upgrade Response Record
///
/// The Upgrade Response Record is a Property Record that is sent in response to an Upgrade Request Record
/// to indicate a willingness to upgrade the protocol stream.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/8f9da3a3-5345-482c-bcb7-543972c1ee4a>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpgradeResponseRecord;

impl Record for UpgradeResponseRecord {
    const RECORD_TYPE: u8 = RecordType::UpgradeResponseRecord as u8;
}

/// MC-NMF 2.2.3.7 Preamble End Record
///
/// The Preamble End Record is a Property Record that is sent to indicate the end of message properties.
/// Envelope Records follow this record.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/2ac9c4ef-a654-4b10-9cf8-b5b8917c654e>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PreambleEndRecord;

impl Record for PreambleEndRecord {
    const RECORD_TYPE: u8 = RecordType::PreambleEndRecord as u8;
}

/// MC-NMF 2.2.3.8 Preamble Ack Record
///
/// The Preamble Ack Record is a Property Record that is sent to indicate receipt of a Preamble End
/// Record and to indicate that all message properties and stream upgrades have been successfully
/// applied. The receiving end is now ready to receive the Envelope Records.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/3ec275c5-49e0-4bec-b751-5cb572c3e7ab>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PreambleAckRecord;

impl Record for PreambleAckRecord {
    const RECORD_TYPE: u8 = RecordType::PreambleAckRecord as u8;
}

/// MC-NMF 2.2.3.9 End Record
///
/// The End Record is a Property Record that indicates that communication over a connection has ended.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/9d691d25-fd3a-41ca-9eb5-241f47a914e5>
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EndRecord;

impl Record for EndRecord {
    const RECORD_TYPE: u8 = RecordType::EndRecord as u8;
}

/// # MC-NMF 2.2.4.1 Sized Envelope Record
///
/// A Sized Envelope Record contains a message of the specified size.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/82159b78-4bbe-4ca8-a707-eeb65d3c6173>
#[derive(Debug, PartialEq)]
pub struct SizedEnvelopeRecord {
    pub(crate) payload: Vec<u8>,
}

impl Record for SizedEnvelopeRecord {
    const RECORD_TYPE: u8 = RecordType::SizedEnvelopeRecord as u8;
}

impl SizedEnvelopeRecord {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }
}

/// # MC-NMF 2.2.4.2 Data Chunk
///
/// A Data Chunk packet is used to transmit a portion of a message payload.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/e72f9eb7-eeaf-48ce-9c07-50f7c5cd856b>
#[derive(Debug, PartialEq)]
pub struct DataChunk {
    pub(crate) payload: Vec<u8>,
}

/// # MC-NMF 2.2.4.3 Unsized Envelope Record
///
/// An Unsized Envelope Record contains a message that is encoded using the encoding indicated by an
/// Envelope Encoding Record that is broken into one or more data chunks of type Data Chunk (section
/// 2.2.4.2). The end of this record is indicated by a single 0x00 octet in place of the start of\
/// the next data chunk.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/5e46160d-c938-4882-bf16-0477449e61e3>
#[derive(Debug, PartialEq)]
pub struct UnsizedEnvelopeRecord {
    pub(crate) chunks: Vec<DataChunk>,
}

impl Record for UnsizedEnvelopeRecord {
    const RECORD_TYPE: u8 = RecordType::UnsizedEnvelopeRecord as u8;
}

impl UnsizedEnvelopeRecord {
    pub const TERMINATOR: u8 = 0x00;
}

/// # MC-NMF 2.2.5 Fault Record
///
/// A Fault Record notifies the sender of an error encountered while processing a message frame.
/// Generation of a Fault Record is informational only.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/337e8351-0854-48d2-864b-97520026c2c6>
#[derive(Debug, PartialEq)]
pub struct FaultRecord(String);

impl Record for FaultRecord {
    const RECORD_TYPE: u8 = RecordType::FaultRecord as u8;
}

impl FaultRecord {
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    pub fn from_utf8(v: &[u8]) -> Result<Self, core::str::Utf8Error> {
        let s = core::str::from_utf8(v)?;
        Ok(Self(s.to_string()))
    }

    pub fn inner_bytes(&self) -> &[u8] {
        let Self(fault) = self;
        fault.as_bytes()
    }
}

/// # MC-NMF 2.2.6 Preamble Message
///
/// To aid description, a Preamble Message is defined for an initial record sequence. The Preamble
/// Message can apply to multiple messages, depending on the mode specified.
///
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/f7b0315d-4843-4376-bf66-265e5756cb5c>
#[derive(Debug, PartialEq)]
pub struct PreambleMessage {
    pub(crate) version: VersionRecord,
    pub(crate) mode: ModeRecord,
    pub(crate) via: ViaRecord,
    pub(crate) encoding: KnownEncodingRecord,
}

impl PreambleMessage {
    /// Create a new PreambleMessage with the default values
    pub fn new<S: Into<String>>(uri: S) -> Self {
        Self {
            version: VersionRecord,
            mode: ModeRecord::Duplex,
            via: ViaRecord(uri.into()),
            encoding: KnownEncodingRecord::Soap12Nbfse,
        }
    }

    pub fn to_wire(&self) -> &[u8] {
        todo!()
    }
}

mod tests {
    use super::*;

    #[test]
    fn it_works() {
        todo!()
    }
}
