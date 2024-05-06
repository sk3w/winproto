use itertools::repeat_n;
use rasn_kerberos::HostAddress;
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(display("Invalid NETBIOS address, must be 1-15 ascii characters"))]
pub struct HostAddressError;

pub trait HostAddressExt {
    fn netbios(address: &str) -> Result<Self, HostAddressError>
    where
        Self: Sized;
}

impl HostAddressExt for HostAddress {
    /// Create new Netbios Host Address (RFC 4120 7.1)
    ///
    /// Netbios addresses are 16-octet addresses typically composed of 1 to 15 alphanumeric
    /// characters and padded with the US-ASCII SPC character (code 32).  The 16th octet MUST be the
    /// US-ASCII NUL character (code 0).  The type of Netbios addresses is twenty (20).
    fn netbios(address: &str) -> Result<Self, HostAddressError> {
        if !address.is_ascii() {
            return Err(HostAddressError);
        }
        if (address.len() == 0) | (address.len() > 15) {
            return Err(HostAddressError);
        }
        let pad_len = 15 - (address.len() % 16);
        let mut address = address.as_bytes().to_vec();
        address.extend(repeat_n(32u8, pad_len));
        address.push(0);
        Ok(Self {
            addr_type: HostAddress::NET_BIOS,
            address: address.into(),
        })
    }
}
