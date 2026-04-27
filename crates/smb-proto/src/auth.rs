//! NTLMv2 server-side authentication and minimal SPNEGO outer envelope.
//!
//! See:
//! * MS-NLMP — NT LAN Manager (NTLM) Authentication Protocol
//! * MS-SPNG — Simple and Protected GSS-API Negotiation Mechanism
//!
//! v1 implements **only** the NTLM (NTLMSSP) mechanism inside SPNEGO.
//! Kerberos is out of scope (revisit in v0.2).

pub mod ntlm;
pub mod spnego;

pub use ntlm::{AuthOutcome, Identity, NtlmServer, UserCreds};
pub use spnego::{
    decode_init_token, decode_resp_token, encode_init_response, encode_resp_token, NegState,
};
