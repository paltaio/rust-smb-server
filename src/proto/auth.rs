//! NTLMv2 server-side authentication and minimal SPNEGO outer envelope.
//!
//! See:
//! * MS-NLMP - NT LAN Manager (NTLM) Authentication Protocol
//! * MS-SPNG - Simple and Protected GSS-API Negotiation Mechanism
//!
//! Only the NTLM (NTLMSSP) mechanism inside SPNEGO is implemented. Kerberos
//! is not supported.

pub mod ntlm;
pub mod spnego;
