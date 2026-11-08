//! NTLMv2 server-side authentication and minimal SPNEGO outer envelope.
//!
//! See:
//! * MS-NLMP - NT LAN Manager (NTLM) Authentication Protocol
//! * MS-SPNG - Simple and Protected GSS-API Negotiation Mechanism
//!
//! NTLM (NTLMSSP) is always built; Kerberos v5 is built with the `krb5` feature, and the two are
//! offered side by side in SPNEGO so a domain client takes the mechanism its policy prefers.

#[cfg(feature = "krb5")]
pub mod kerberos;
pub mod ntlm;
pub mod spnego;
