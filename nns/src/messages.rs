use bytes::Bytes;

/// # Handshake Message (MS-NNS 2.2.1)
/// 
/// Handshake messages are used to carry GSS-API security tokens used to
/// establish a security context.
/// 
/// [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/3e77f3ac-db7e-4c76-95de-911dd280947b]
#[derive(Debug, PartialEq)]
pub enum HandshakeMessage {
    HandshakeDone { auth_payload: Vec<u8> },
    /// When the Handshake message has a MessageId of HandshakeError, the
    /// AuthPayload field MUST have a length of 8 bytes, and contain either an
    /// HRESULT error code describing an error encountered by the security
    /// package or the Win32 error code ERROR_TRUST_FAILURE (0x000006FE)
    /// indicating that the security package was able to successfully
    /// authenticate, but the negotiated security parameters were unacceptable
    /// to the remote side.
    HandshakeError { error_code: u32 },
    HandshakeInProgress { auth_payload: Vec<u8> },
}

impl HandshakeMessage {
    pub const HANDSHAKE_DONE: u8 = 0x14;
    pub const HANDSHAKE_ERROR: u8 = 0x15;
    pub const HANDSHAKE_IN_PROGRESS: u8 = 0x16;
}

/// # Data Message (MS-NNS 2.2.2)
///
/// Data messages are used to carry application data that has been signed
/// and/or encrypted by the negotiated security mechanism.
///
/// [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/decab651-1330-4ce9-bac5-96d19310cb40]
#[derive(Debug, PartialEq)]
pub struct DataMessage {
    pub(crate) payload: Bytes
}
