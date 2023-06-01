use rasn_kerberos::{AsRep, AsReq, TgsRep};

use crate::structures::AsReqExt;

pub struct HashcatHash {
    // mode: u32,
    // short_name: String,
    // name: String,
    output: String,
}

impl core::fmt::Display for HashcatHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.output)
    }
}

#[derive(Debug)]
pub enum RoastError {
    InvalidData,
    NoPaEncTimestamp,
    UnsupportedEtype,
    UnsupportedTimestampLength,
}

pub trait Roastable {
    fn dump_to_hashcat(&self) -> Result<HashcatHash, RoastError>;
}

impl Roastable for AsReq {
    fn dump_to_hashcat(&self) -> Result<HashcatHash, RoastError> {
        // Hashcat supports etype 17, 18, and 23
        let user = self.get_cname().ok_or(RoastError::InvalidData)?;
        let realm = self.get_realm();
        let pa_enc_timestamp = self
            .get_pa_enc_timestamp()
            .ok_or(RoastError::NoPaEncTimestamp)?;
        match self.get_pa_etype() {
            // Kerberos 5, etype 23, AS-REQ Pre-Auth
            // hashcat mode 7500
            // output format:
            // $krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835
            Some(23) => {
                // Hashcat requires the "timestamp" + checksum to be exactly length 36 + 16 bytes
                if pa_enc_timestamp.cipher.len() != 52 {
                    return Err(RoastError::UnsupportedTimestampLength);
                }
                let checksum = &pa_enc_timestamp.cipher.slice(..16);
                let confounder = &pa_enc_timestamp.cipher.slice(16..24);
                let ciphertext = &pa_enc_timestamp.cipher.slice(24..);
                Ok(HashcatHash {
                    output: format!(
                        "$krb5pa$23${user}${realm}$salt${confounder:x}{ciphertext:x}{checksum:x}"
                    ),
                })
            }
            // Kerberos 5, etype 17, Pre-Auth
            // hashcat mode 19800
            // output format:
            // $krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333
            Some(17) => {
                // ciphertext value includes 12 bytes of checksum at the end
                let ciphertext = &pa_enc_timestamp.cipher;
                Ok(HashcatHash {
                    output: format!("$krb5pa$17${user}${realm}${ciphertext:x}"),
                })
            }
            // Kerberos 5, etype 18, Pre-Auth
            // hashcat mode 19900
            // output format:
            // $krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770
            Some(18) => {
                // ciphertext value includes 12 bytes of checksum at the end
                let ciphertext = &pa_enc_timestamp.cipher;
                Ok(HashcatHash {
                    output: format!("$krb5pa$18${user}${realm}${ciphertext:x}"),
                })
            }
            _ => Err(RoastError::UnsupportedEtype),
        }
    }
}

impl Roastable for AsRep {
    fn dump_to_hashcat(&self) -> Result<HashcatHash, RoastError> {
        todo!()
    }
}

impl Roastable for TgsRep {
    fn dump_to_hashcat(&self) -> Result<HashcatHash, RoastError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn asreq_23_ref_dump_to_hashcat() {
        let as_req = hex!(
            "6a 82 01 1e 30 82 01 1a a1 03 02 01 05 a2 03 02"
            "01 0a a3 5f 30 5d 30 48 a1 03 02 01 02 a2 41 04"
            "3f 30 3d a0 03 02 01 17 a2 36 04 34 03 df 30 25"
            "ab 5a 9d fc 30 31 e8 93 c4 00 20 08 da f3 24 dc"
            "ce c7 37 39 f6 e4 9e f8 fd e6 0a 9f 9d ff f5 05"
            "51 ff 5a 7e 96 9c 6e 39 5f 18 b8 42 fb 17 c3 b5"
            "30 11 a1 04 02 02 00 80 a2 09 04 07 30 05 a0 03"
            "01 01 ff a4 81 ac 30 81 a9 a0 07 03 05 00 40 81"
            "00 10 a1 0f 30 0d a0 03 02 01 01 a1 06 30 04 1b"
            "02 75 35 a2 08 1b 06 44 45 4e 59 44 43 a3 1b 30"
            "19 a0 03 02 01 02 a1 12 30 10 1b 06 6b 72 62 74"
            "67 74 1b 06 44 45 4e 59 44 43 a5 11 18 0f 32 30"
            "33 37 30 39 31 33 30 32 34 38 30 35 5a a6 11 18"
            "0f 32 30 33 37 30 39 31 33 30 32 34 38 30 35 5a"
            "a7 06 02 04 32 ee 80 b3 a8 19 30 17 02 01 17 02"
            "02 ff 7b 02 01 80 02 01 03 02 01 01 02 01 18 02"
            "02 ff 79 a9 1d 30 1b 30 19 a0 03 02 01 14 a1 12"
            "04 10 58 50 31 20 20 20 20 20 20 20 20 20 20 20"
            "20 20"
        );
        let as_req: AsReq = rasn::der::decode(&as_req).unwrap();
        let hash = as_req.dump_to_hashcat().unwrap();
        let expected = "$krb5pa$23$u5$DENYDC$salt$daf324dccec73739f6e49ef8fde60a9f9dfff50551ff5a7e969c6e395f18b842fb17c3b503df3025ab5a9dfc3031e893c4002008";
        assert_eq!(hash.output, expected);
    }

    #[test]
    fn asreq_23_dump_to_hashcat() {
        let as_req = hex!(
            "6a 82 01 13"
            "30 82 01 0f a1 03 02 01 05 a2 03 02 01 0a a3 5f"
            "30 5d 30 48 a1 03 02 01 02 a2 41 04 3f 30 3d a0"
            "03 02 01 17 a2 36 04 34 4c 51 99 53 18 bd 5e bb"
            "fe 18 b9 68 2d 1f 68 34 44 09 0e 0c 52 e8 71 d5"
            "1e 6c 5f b5 b9 5d e2 7e 4b 5b aa 7c 6d e2 7a 6c"
            "11 4e ca 77 3e 9f 6c 15 9a 38 42 af 30 11 a1 04"
            "02 02 00 80 a2 09 04 07 30 05 a0 03 01 01 ff a4"
            "81 a1 30 81 9e a0 07 03 05 00 40 81 00 10 a1 14"
            "30 12 a0 03 02 01 01 a1 0b 30 09 1b 07 76 61 67"
            "72 61 6e 74 a2 11 1b 0f 57 49 4e 44 4f 4d 41 49"
            "4e 2e 4c 4f 43 41 4c a3 24 30 22 a0 03 02 01 02"
            "a1 1b 30 19 1b 06 6b 72 62 74 67 74 1b 0f 57 49"
            "4e 44 4f 4d 41 49 4e 2e 4c 4f 43 41 4c a5 11 18"
            "0f 32 30 33 37 30 39 31 33 30 32 34 38 30 35 5a"
            "a6 11 18 0f 32 30 33 37 30 39 31 33 30 32 34 38"
            "30 35 5a a7 03 02 01 03 a8 05 30 03 02 01 17 a9"
            "12 30 10 30 0e a0 03 02 01 14 a1 07 04 05 57 49"
            "4e 31 30"
        );
        let as_req: AsReq = rasn::der::decode(&as_req).unwrap();
        let hash = as_req.dump_to_hashcat().unwrap();
        let expected = "$krb5pa$23$vagrant$WINDOMAIN.LOCAL$salt$44090e0c52e871d51e6c5fb5b95de27e4b5baa7c6de27a6c114eca773e9f6c159a3842af4c51995318bd5ebbfe18b9682d1f6834";
        assert_eq!(hash.output, expected);
    }
}
