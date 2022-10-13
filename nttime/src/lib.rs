//! # nttime - An implementation of the Windows NT Time Format
//!
//! This data type (also known as "FILETIME") is used by Microsoft Active Directory, NTLM
//! authentication, LDAP, NTFS, etc. For more information, see the following:
//!
//! * <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf>
//! * <https://docs.microsoft.com/en-us/windows/win32/sysinfo/file-times>
//! * <https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime>

#![no_std]

use chrono::{DateTime, Duration, TimeZone, Utc};

/// Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)
#[derive(Clone, Debug, PartialEq)]
pub struct NTTime {
    inner: u64,
}

impl NTTime {
    //const NT_EPOCH: DateTime<Utc> = Utc.ymd(1601, 01, 01).and_hms(0, 0, 0);

    /// Creates a new NTTime value set to the current time
    pub fn now() -> Self {
        NTTime::from(Utc::now())
    }

    /// Encodes the NTTime value to a byte array suitable for network protocols
    pub fn encode(&self) -> [u8; 8] {
        self.inner.to_le_bytes()
    }
}

impl From<u64> for NTTime {
    /// Raw constructor for debugging / tests
    fn from(inner: u64) -> Self {
        Self { inner }
    }
}

impl From<DateTime<Utc>> for NTTime {
    fn from(datetime: DateTime<Utc>) -> Self {
        let nt_epoch = Utc.ymd(1601, 01, 01).and_hms(0, 0, 0);
        let seconds: u64 = datetime
            .signed_duration_since(nt_epoch)
            .num_seconds()
            .unsigned_abs();
        let nanos: u64 = datetime.timestamp_subsec_nanos().into();
        let inner = (seconds * 10_000_000) + nanos;
        Self { inner }
    }
}

impl From<NTTime> for DateTime<Utc> {
    fn from(nt_time: NTTime) -> Self {
        let seconds: i64 = (nt_time.inner / 10_000_000) as i64;
        let nanos: i64 = (nt_time.inner % 10_000_000) as i64;
        Utc.ymd(1601, 1, 1)
            .and_hms(0, 0, 0)
            .checked_add_signed(Duration::seconds(seconds))
            .and_then(|dt| dt.checked_add_signed(Duration::nanoseconds(nanos)))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    /// Can test conversions using <https://www.epochconverter.com/ldap>
    use super::*;

    #[test]
    fn example_conversion_works() {
        // https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/convert-datetime-attributes-to-standard-format#example
        let nt_time = NTTime {
            inner: 128271382742968750,
        };
        let datetime = Utc.ymd(2007, 6, 24).and_hms_nano(5, 57, 54, 2968750);
        assert_eq!(NTTime::from(datetime), nt_time);
        assert_eq!(DateTime::<Utc>::from(nt_time), datetime);
    }
}
