// PA-DATA types
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_ETYPE_INFO2: i32 = 19;
pub const PA_PAC_REQUEST: i32 = 128;

// ETYPEs
pub const ETYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17; // 0x11
pub const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18; // 0x11
pub const ETYPE_RC4_HMAC_MD5: i32 = 23; // 0x17
pub const ETYPE_RC4_HMAC_MD5_EXP: i32 = 24; // 0x18
pub const ETYPE_RC4_MD4: i32 = -128; // 0x80

// RFC 4120 7.5.1 Key Usage Numbers
pub const KEY_USAGE_PA_ENC_TIMESTAMP: i32 = 1;
pub const KEY_USAGE_AS_REP_ENC_PART: i32 = 3;
pub const KEY_USAGE_TGS_REP_ENC_PART: i32 = 8;

// Error codes
pub const KDC_ERR_ETYPE_NOTSUPP: i32 = 14;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KDC_ERR_GENERIC: i32 = 60;
