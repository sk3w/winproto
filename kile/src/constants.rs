// TODO: Add more from https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml

// PA-DATA types
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_ETYPE_INFO2: i32 = 19;
pub const PA_PAC_REQUEST: i32 = 128;

// ETYPEs
pub const ETYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17; // 0x11
pub const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18; // 0x12
pub const ETYPE_RC4_HMAC_MD5: i32 = 23; // 0x17
pub const ETYPE_RC4_HMAC_MD5_EXP: i32 = 24; // 0x18
pub const ETYPE_RC4_MD4: i32 = -128; // 0x80

// RFC 4120 6.2 Principal Names
/// Name type not known
pub const NT_UNKNOWN: i32 = 0;
/// Just the name of the principal as in DCE, or for users
pub const NT_PRINCIPAL: i32 = 1;
/// Service and other unique instance (krbtgt)
pub const NT_SRV_INST: i32 = 2;
/// Service with host name as instance (telnet, rcommands)
pub const NT_SRV_HST: i32 = 3;
/// Service with host as remaining components
pub const NT_SRV_XHST: i32 = 4;
/// Unique ID
pub const NT_UID: i32 = 5;
/// Encoded X.509 Distinguished name [RFC2253]
pub const NT_X500_PRINCIPAL: i32 = 6;
/// Name in form of SMTP email name (e.g., user@example.com)
pub const NT_SMTP_NAME: i32 = 7;
/// Enterprise name - may be mapped to principal name
pub const NT_ENTERPRISE: i32 = 10;

// Additional RFC and Windows-specific Principal Names
// https://github.com/heimdal/heimdal/blob/master/lib/asn1/krb5.asn1
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-kerberos.c
// https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_external_name
/// Wellknown
pub const NT_WELLKNOWN: i32 = 11;
/// Domain based service with host name as instance (RFC5179)
pub const NT_SRV_HST_DOMAIN: i32 = 12;
/// Windows NT 4.0–style name
pub const NT_MS_PRINCIPAL: i32 = -128;
/// Windows NT 4.0–style name with SID (same as NT_MS_PRINCIPAL?)
pub const NT_MS_PRINCIPAL_AND_ID: i32 = -129;
/// Windows 2000 UPN and SID (same as NT_X500_PRINCIPAL?)
pub const NT_ENT_PRINCIPAL_AND_ID: i32 = -130;
/// Principal name and SID (MS specific)
pub const NT_PRINCIPAL_AND_SID: i32 = -131;
/// SPN and SID (MS specific)
pub const NT_SRV_INST_AND_SID: i32 = -132;
/// NTLM name, realm is domain
pub const NT_NTLM: i32 = -1200;
/// X509 general name (base64 encoded)
pub const NT_X509_GENERAL_NAME: i32 = -1201;
/// not used?
pub const NT_GSS_HOSTBASED_SERVICE: i32 = -1202;
/// name is actually a uuid pointing to ccache, use client name in cache
pub const NT_CACHE_UUID: i32 = -1203;
/// Internal: indicates that name canonicalization is needed
pub const NT_SRV_HST_NEEDS_CANON: i32 = -195894762;


// RFC 4120 7.5.1 Key Usage Numbers
pub const KEY_USAGE_PA_ENC_TIMESTAMP: i32 = 1;
pub const KEY_USAGE_AS_REP_ENC_PART: i32 = 3;
pub const KEY_USAGE_TGS_REP_ENC_PART: i32 = 8;

// RFC 4120 7.5.9 Error Codes
// Also at https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-admin/Kerberos-V5-Library-Error-Codes.html
/// KDC has no support for encryption type
pub const KDC_ERR_ETYPE_NOTSUPP: i32 = 14;
/// Pre-authentication information was invalid
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
/// Additional pre-authentication required
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
/// Generic error (description in e-text)
pub const KRB_ERR_GENERIC: i32 = 60;

// IAKerb error codes
pub const KRB_AP_ERR_IAKERB_KDC_NOT_FOUND: i32 = 85;
pub const KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE: i32 = 86;
