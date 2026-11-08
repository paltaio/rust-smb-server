//! Kerberos v5 acceptor for SESSION_SETUP (MS-SMB2 3.3.5.5.3, RFC 4120).
//!
//! # Why this is a separate branch and not another NTLM step
//!
//! Kerberos is a **one-shot** mechanism from the server's point of view: the client already holds a
//! service ticket - it got it from the KDC by asking for `cifs/<host>` - so the first SESSION_SETUP
//! carries a complete AP-REQ and the server either accepts it or does not. There is no
//! CHALLENGE_MESSAGE, no second round, and no place to fail slowly. NTLM's three messages and its
//! pending-auth table have no counterpart here.
//!
//! What the client may still ask for is **mutual authentication**: an AP-REP that proves the server
//! holds the service key. Windows always asks for it over SMB, so a server that skips the AP-REP is
//! refused by the client even though the ticket was good.
//!
//! # What this module does not do
//!
//! The DER, the GSS-API framing, the token ids, the AP-REP envelope and the PAC all live in the
//! `krb5` crate, which was extracted from a working NFS server and whose acceptor is tested against
//! tokens recorded from a live MIT KDC for all four AES enctypes.
//!
//! An earlier version of this module hand-rolled all of it over `rskrb5`, and each of its five
//! defects is a paragraph in that crate's source: the `[APPLICATION 0]` wrapper, the two-byte token
//! id between the OID and the message, the AP-REP envelope, the initiator subkey that must become
//! the session key, and a PAC that a realm which is not Active Directory never issues. What is left
//! here is the part that belongs to SMB: which key the session signs with, and what a logon yields.
//!
//! # The session key
//!
//! SMB derives its signing key and its encryption keys from a session key. The ticket has one, but
//! when the client's authenticator carries a **subkey**, RFC 4121 §2 makes that subkey the base key
//! for every per-message operation - and SMB signing is one. `KerberosContext::base_key` is exactly
//! that choice already made, so this module takes it rather than `session_key`.
//!
//! Taking the ticket key where a subkey was offered produces a session whose first signed message
//! the client rejects as "Bad SMB2 signature": mutual authentication succeeds and nothing after it
//! does. That is not hypothetical - it is what the stand showed before this module was rewritten.
//!
//! MS-SMB2 3.2.5.3.1 says the SMB session key *is* the Kerberos session key, and the KDFs in 3.1.4.2
//! take its first 128 bits for AES-128-CMAC, AES-128-CCM and AES-128-GCM - the only ciphers this
//! server offers. The first sixteen bytes are therefore right for every enctype a modern KDC issues,
//! and [`SMB_SESSION_KEY_LEN`] says why the tail is not used.
use krb5::{KerberosContext, Keytab};

/// 128 bits: what every signing and encryption KDF this server implements takes.
const SMB_SESSION_KEY_LEN: usize = 16;

/// What a validated AP-REQ proves about the client.
#[derive(Debug, Clone)]
pub struct KerberosIdentity {
    /// The client principal's first component: `alice` for `alice@EXAMPLE.COM`.
    pub user: String,
    /// The client principal's realm, as the KDC spells it.
    pub realm: String,
    /// The base key, truncated to the length SMB's KDFs consume.
    pub session_key: [u8; SMB_SESSION_KEY_LEN],
    /// An AP-REP to return for mutual authentication, when the client asked for it.
    pub ap_rep: Option<Vec<u8>>,
}

/// Why an AP-REQ was refused.
#[derive(Debug)]
pub enum KerberosError {
    /// The keytab could not be read, or held no keys.
    Keytab(String),
    /// The AP-REQ was malformed, expired, for another service, or its PAC did not verify.
    Rejected(String),
    /// The ticket was good but its base key is shorter than SMB's KDFs need.
    ///
    /// Three-byte DES and the two-byte exports do exist in old keytabs; refusing them with a reason
    /// is better than padding, because padding would produce a session that signs and never verifies.
    ShortKey { enctype: i32, len: usize },
}

impl std::fmt::Display for KerberosError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keytab(detail) => write!(formatter, "the keytab could not be read: {detail}"),
            Self::Rejected(detail) => write!(formatter, "the AP-REQ was refused: {detail}"),
            Self::ShortKey { enctype, len } => write!(
                formatter,
                "the session base key is {len} bytes (enctype {enctype}) and SMB needs {SMB_SESSION_KEY_LEN}"
            ),
        }
    }
}

impl std::error::Error for KerberosError {}

/// An acceptor over one service keytab.
pub struct KerberosAcceptor {
    keytab: Keytab,
}

impl std::fmt::Debug for KerberosAcceptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KerberosAcceptor")
            .field("keys", &self.keytab.keys().len())
            .finish()
    }
}

impl KerberosAcceptor {
    /// An acceptor from a keytab file, as `ktutil` or `samba-tool domain exportkeytab` writes it.
    ///
    /// One constructor and not two: the keys are read here, once, at `build()` time. A server that
    /// re-read the file at first logon would be a server whose credentials somebody else can swap
    /// under it, and a second way to construct an acceptor is a second place to forget that.
    pub fn from_keytab(path: impl AsRef<std::path::Path>) -> Result<Self, KerberosError> {
        let keytab =
            Keytab::load(path.as_ref()).map_err(|e| KerberosError::Keytab(e.to_string()))?;
        if keytab.keys().is_empty() {
            // An empty keytab accepts nothing, and a server that starts with one looks configured
            // while refusing every ticket. That is worse than a start that fails.
            return Err(KerberosError::Keytab(
                "the keytab holds no keys".to_string(),
            ));
        }
        Ok(Self { keytab })
    }

    /// The principals the keytab holds, for a diagnostic log line.
    pub fn principals(&self) -> Vec<String> {
        self.keytab
            .keys()
            .iter()
            .map(|key| format!("{}@{}", key.principal, key.realm))
            .collect()
    }

    /// Accepts an AP-REQ from a SESSION_SETUP token.
    ///
    /// Two framings reach here and both are legal: a GSS-API token (`[APPLICATION 0] { OID, TOK_ID,
    /// AP-REQ }`), which is what an MIT client puts in SPNEGO's mechanism token, and a bare AP-REQ,
    /// which a protocol carrying Kerberos without GSS-API sends. The first byte says which, so the
    /// choice is made rather than guessed by trying one and falling back - a fallback would re-parse
    /// the same bytes after a genuine failure and blur the reason.
    pub fn accept(&self, token: &[u8]) -> Result<KerberosIdentity, KerberosError> {
        const TAG_APPLICATION_0: u8 = 0x60;
        const TAG_AP_REQ: u8 = 0x6e;

        let accepted = match token.first() {
            Some(&TAG_APPLICATION_0) => KerberosContext::accept_token(&self.keytab, token),
            Some(&TAG_AP_REQ) => {
                KerberosContext::accept_ap_req(&self.keytab, token, &Default::default())
            }
            _ => {
                return Err(KerberosError::Rejected(
                    "the token is neither a GSS-API AP-REQ nor a bare AP-REQ".to_string(),
                ));
            }
        };

        let (context, ap_rep) = accepted.map_err(|e| KerberosError::Rejected(e.to_string()))?;

        // `base_key`, not `session_key`: RFC 4121 §2 makes the initiator's subkey the key for every
        // per-message operation when one was offered, and SMB signing is one. The crate has already
        // made that choice; taking `session_key` here would undo it and break every signed reply.
        let key = &context.base_key;
        if key.len() < SMB_SESSION_KEY_LEN {
            return Err(KerberosError::ShortKey {
                enctype: context.base_key_enctype as i32,
                len: key.len(),
            });
        }
        let mut session_key = [0u8; SMB_SESSION_KEY_LEN];
        session_key.copy_from_slice(&key[..SMB_SESSION_KEY_LEN]);

        // `alice@EXAMPLE.COM` or `alice/admin@EXAMPLE.COM`: SMB's user name is the first component,
        // which is the account name a Windows client logs on with. Split at the last `@`, because a
        // principal name may itself hold one.
        let (name, realm) = match context.client_principal.rsplit_once('@') {
            Some((name, realm)) => (name.to_string(), realm.to_string()),
            None => (
                context.client_principal.clone(),
                context.client_realm.clone(),
            ),
        };
        let user = name.split('/').next().unwrap_or(&name).to_string();

        Ok(KerberosIdentity {
            user,
            realm,
            session_key,
            // Empty means "the client did not ask for mutual authentication": the crate builds an
            // AP-REP only for MUTUAL-REQUIRED, and an empty reply is not a token to send.
            ap_rep: (!ap_rep.is_empty()).then_some(ap_rep),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keytab holding one principal, written the way `kadmin.local -q ktadd` writes it: a version
    /// byte pair, then per entry a length and its body - component count, counted strings for the
    /// realm and each component, name type, timestamp, key version, enctype and the key.
    fn keytab_with_one_principal() -> Vec<u8> {
        fn counted(out: &mut Vec<u8>, text: &str) {
            out.extend_from_slice(&(text.len() as i16).to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }

        let mut body = Vec::new();
        body.extend_from_slice(&2i16.to_be_bytes()); // components: cifs, smbhost
        counted(&mut body, "EXAMPLE.COM");
        counted(&mut body, "cifs");
        counted(&mut body, "smbhost");
        body.extend_from_slice(&1i32.to_be_bytes()); // name type 1: KRB5_NT_PRINCIPAL
        body.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        body.push(2); // key version
        body.extend_from_slice(&17i16.to_be_bytes()); // aes128-cts-hmac-sha1-96
        body.extend_from_slice(&16i16.to_be_bytes());
        body.extend_from_slice(&[0x11u8; 16]);

        let mut out = vec![0x05, 0x02];
        out.extend_from_slice(&(body.len() as i32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// The crate loads keytabs from a path, so a fixture is a file. Removed before returning.
    fn acceptor_from(bytes: &[u8]) -> Result<KerberosAcceptor, KerberosError> {
        let name = format!(
            "smb-krb-test-{}-{:?}.keytab",
            std::process::id(),
            std::thread::current().id()
        );
        let path = std::env::temp_dir().join(name.replace(['(', ')', ' '], ""));
        std::fs::write(&path, bytes).expect("write keytab");
        let acceptor = KerberosAcceptor::from_keytab(&path);
        let _ = std::fs::remove_file(&path);
        acceptor
    }

    #[test]
    fn the_keytab_is_parsed_and_its_principal_named() {
        let acceptor = acceptor_from(&keytab_with_one_principal()).expect("parsed");
        assert_eq!(acceptor.principals(), vec!["cifs/smbhost@EXAMPLE.COM"]);
    }

    #[test]
    fn a_keytab_with_no_keys_is_refused_rather_than_starting_a_server_that_accepts_nothing() {
        // A server that started on this would look configured while refusing every logon, and the
        // client would report an access failure rather than a configuration error.
        let refused = acceptor_from(&[0x05, 0x02, 0, 0, 0, 0]).expect_err("refused");
        assert!(refused.to_string().contains("no keys"), "{refused}");
    }

    #[test]
    fn a_keytab_that_is_not_a_keytab_is_refused() {
        let refused = acceptor_from(b"this is not a keytab").expect_err("refused");
        assert!(refused.to_string().contains("keytab"), "{refused}");
    }

    #[test]
    fn nothing_that_is_not_a_ticket_is_accepted() {
        // The one property an acceptor must have: nonsense in, refusal out. An acceptor that took a
        // frame it could not parse for a valid one would authenticate anyone who sent random bytes.
        let acceptor = acceptor_from(&keytab_with_one_principal()).expect("parsed");

        for garbage in [
            &b""[..],
            &b"\x00"[..],
            &b"not-a-ticket"[..],
            &[0xff; 64][..],
            // A bare AP-REQ tag with nothing behind it: well-framed and empty, which a lenient
            // parser would read as a ticket with no authenticator.
            &[0x6e, 0x02, 0x00, 0x00][..],
        ] {
            assert!(
                acceptor.accept(garbage).is_err(),
                "garbage was accepted: {garbage:?}"
            );
        }
    }

    #[test]
    fn a_frame_that_is_neither_framing_is_refused_with_the_reason() {
        let acceptor = acceptor_from(&keytab_with_one_principal()).expect("parsed");
        let refused = acceptor
            .accept(&[0x30, 0x03, 0x02, 0x01, 0x05])
            .expect_err("refused");
        assert!(
            refused
                .to_string()
                .contains("neither a GSS-API AP-REQ nor a bare AP-REQ"),
            "{refused}"
        );
    }

    #[test]
    fn a_short_base_key_is_refused_with_the_reason_and_not_padded() {
        // Padding a DES key to sixteen bytes produces a session whose signatures never verify, and
        // the client would report "access denied" rather than "the server cannot do this enctype".
        let error = KerberosError::ShortKey { enctype: 1, len: 8 };
        let text = error.to_string();
        assert!(text.contains("8 bytes"), "{text}");
        assert!(text.contains("16"), "{text}");
    }
}
