use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use chrono::Utc;
use rasn::der;
use rasn_kerberos::{
    AsRep, EncKrbCredPart, EncryptedData, EncryptionKey, KerberosTime, KrbCred, KrbCredInfo,
};

/// Deserialize a RFC4120 KRB_CRED structure from a file ("kirbi")
///
/// <https://www.rfc-editor.org/rfc/rfc4120#section-5.8>
pub fn read_kirbi(path: &Path) -> io::Result<KrbCred> {
    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    let buf: Vec<u8> = buf_reader.bytes().flatten().collect();
    let krb_cred: KrbCred = der::decode(buf.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to decode kirbi file"))?;
    Ok(krb_cred)
}

/// Serialize a RFC4120 KRB_CRED structure to a file ("kirbi")
///
/// <https://www.rfc-editor.org/rfc/rfc4120#section-5.8>
pub fn write_kirbi(krb_cred: KrbCred, path: &Path) -> io::Result<()> {
    let mut file = File::create(path)?;
    let buf = der::encode(&krb_cred)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to encode KrbCred"))?;
    file.write_all(&buf)?;
    Ok(())
}

/// Serialize an AS-REP to a RFC4120 KRB_CRED structure using the TGT session key
pub fn write_tgt_to_kirbi(
    as_rep: AsRep,
    session_key: EncryptionKey,
    path: &Path,
) -> io::Result<()> {
    let krb_cred_info = KrbCredInfo {
        key: session_key.clone(),
        prealm: Some(as_rep.0.crealm),
        pname: Some(as_rep.0.cname),
        flags: None,
        auth_time: None,
        start_time: None,
        end_time: None,
        renew_till: None,
        srealm: Some(as_rep.0.ticket.realm.clone()),
        sname: Some(as_rep.0.ticket.sname.clone()),
        caddr: None,
    };
    let enc_krb_cred_part = EncKrbCredPart {
        ticket_info: vec![krb_cred_info],
        nonce: None,
        timestamp: Some(KerberosTime(Utc::now().into())),
        usec: None,
        sender_address: None,
        recipient_address: None,
    };
    let cipher = der::encode(&enc_krb_cred_part).unwrap();
    let enc_part = EncryptedData {
        etype: session_key.r#type,
        kvno: None,
        cipher: cipher.into(),
    };
    let krb_cred = KrbCred {
        pvno: 5.into(),
        msg_type: 22.into(),
        tickets: vec![as_rep.0.ticket],
        enc_part: enc_part,
    };
    write_kirbi(krb_cred, path)
}

/// Deserialize an AS-REP message from a file
pub fn read_asrep(path: PathBuf) -> io::Result<AsRep> {
    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    let buf: Vec<u8> = buf_reader.bytes().flatten().collect();
    let as_rep: AsRep = der::decode(buf.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to decode kirbi file"))?;
    Ok(as_rep)
}

/// Serialize an AS-REP message to a file
pub fn write_asrep(as_rep: &AsRep, path: PathBuf) -> io::Result<()> {
    let mut file = File::create(&path)?;
    let buf = der::encode(as_rep)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to encode AsRep value"))?;
    file.write_all(&buf)?;
    Ok(())
}
