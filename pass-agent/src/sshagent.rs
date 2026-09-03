//! The OpenSSH agent protocol, served from keys held in the vault.
//!
//! Wire format is draft-miller-ssh-agent: every message is a big-endian
//! `uint32` length followed by that many bytes, of which the first is the
//! message type. Strings inside a message are themselves length-prefixed.
//!
//! `pass`'s agent is deliberately **read-only**: `ssh-add` cannot push a key
//! into it, remove one, or wipe it. Keys live in the vault and are managed
//! with `pass ssh`, so an agent that accepted `ADD_IDENTITY` would be
//! offering a second, invisible place for a private key to live — exactly the
//! situation a password manager exists to prevent. Those requests get an
//! explicit `SSH_AGENT_FAILURE`, which is a response the protocol defines and
//! `ssh-add` reports plainly.

use std::io::{self, Read, Write};

// Message numbers from draft-miller-ssh-agent §5.1.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// Refuse to allocate for an absurd length claim. Real agent messages are
/// bounded by the size of a key blob plus the data being signed; OpenSSH
/// itself caps agent messages at 256 KiB.
const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// A request this agent understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequest {
    /// "What keys do you have?"
    RequestIdentities,
    /// "Sign this with the key whose public blob is `key_blob`."
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Anything else, carried through so the server can answer `FAILURE`
    /// and log *which* request it turned down.
    Unsupported(u8),
}

/// Parse a message body (length prefix already stripped).
pub fn parse_request(payload: &[u8]) -> io::Result<AgentRequest> {
    let mut reader = Reader::new(payload);
    let kind = reader.read_u8()?;

    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(AgentRequest::RequestIdentities),
        SSH_AGENTC_SIGN_REQUEST => {
            let key_blob = reader.read_string()?.to_vec();
            let data = reader.read_string()?.to_vec();
            // OpenSSH always sends flags, but tolerate their absence rather
            // than failing a signature over a missing "no flags" word.
            let flags = reader.read_u32().unwrap_or(0);
            Ok(AgentRequest::Sign { key_blob, data, flags })
        }
        other => Ok(AgentRequest::Unsupported(other)),
    }
}

/// Build an `SSH_AGENT_IDENTITIES_ANSWER` listing `(public key blob, comment)`.
pub fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    put_u32(&mut out, keys.len() as u32);
    for (blob, comment) in keys {
        put_string(&mut out, blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

/// Build an `SSH_AGENT_SIGN_RESPONSE` around an already-encoded signature
/// blob (`string algorithm, string signature`).
pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut out, signature);
    out
}

pub fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

pub fn success() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

/// Read one length-prefixed message. `Ok(None)` means the peer closed the
/// connection cleanly between messages.
pub fn read_message(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty agent message"));
    }
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent message of {len} bytes exceeds the {MAX_MESSAGE_LEN} byte limit"),
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Write one length-prefixed message.
pub fn write_message(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let mut framed = Vec::with_capacity(4 + payload.len());
    put_u32(&mut framed, payload.len() as u32);
    framed.extend_from_slice(payload);
    stream.write_all(&framed)?;
    stream.flush()
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Bounds-checked cursor over a message body. Every read returns an error
/// rather than panicking on a short or malformed message, because the input
/// is whatever a local process chose to send.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated agent message"))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_string(&mut self) -> io::Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u8, body: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![kind];
        for part in body {
            put_string(&mut out, part);
        }
        out
    }

    #[test]
    fn parses_a_request_identities_message() {
        let request = parse_request(&[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(request, AgentRequest::RequestIdentities);
    }

    #[test]
    fn parses_a_sign_request_with_flags() {
        let mut payload = message(SSH_AGENTC_SIGN_REQUEST, &[b"key-blob", b"data-to-sign"]);
        put_u32(&mut payload, 4);

        assert_eq!(
            parse_request(&payload).unwrap(),
            AgentRequest::Sign {
                key_blob: b"key-blob".to_vec(),
                data: b"data-to-sign".to_vec(),
                flags: 4,
            }
        );
    }

    #[test]
    fn a_sign_request_without_trailing_flags_defaults_to_zero() {
        let payload = message(SSH_AGENTC_SIGN_REQUEST, &[b"key", b"data"]);
        match parse_request(&payload).unwrap() {
            AgentRequest::Sign { flags, .. } => assert_eq!(flags, 0),
            other => panic!("expected a sign request, got {other:?}"),
        }
    }

    #[test]
    fn unknown_message_types_are_reported_not_guessed() {
        assert_eq!(
            parse_request(&[SSH_AGENTC_ADD_IDENTITY]).unwrap(),
            AgentRequest::Unsupported(SSH_AGENTC_ADD_IDENTITY)
        );
        assert_eq!(
            parse_request(&[SSH_AGENTC_EXTENSION]).unwrap(),
            AgentRequest::Unsupported(SSH_AGENTC_EXTENSION)
        );
    }

    #[test]
    fn truncated_messages_are_errors_not_panics() {
        // Empty body.
        assert!(parse_request(&[]).is_err());
        // Claims an 8-byte string but supplies 3.
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        put_u32(&mut payload, 8);
        payload.extend_from_slice(b"abc");
        assert!(parse_request(&payload).is_err());
    }

    #[test]
    fn a_string_length_that_overflows_is_rejected() {
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        put_u32(&mut payload, u32::MAX);
        assert!(parse_request(&payload).is_err());
    }

    #[test]
    fn identities_answer_has_the_documented_layout() {
        let keys = vec![(b"blob-one".to_vec(), "first@host".to_string())];
        let answer = identities_answer(&keys);

        let mut reader = Reader::new(&answer);
        assert_eq!(reader.read_u8().unwrap(), SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(reader.read_u32().unwrap(), 1);
        assert_eq!(reader.read_string().unwrap(), b"blob-one");
        assert_eq!(reader.read_string().unwrap(), b"first@host");
    }

    #[test]
    fn an_empty_agent_answers_with_zero_keys() {
        let answer = identities_answer(&[]);
        assert_eq!(answer, vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]);
    }

    #[test]
    fn framing_roundtrips() {
        let payload = identities_answer(&[(b"k".to_vec(), "c".to_string())]);

        let mut wire = Vec::new();
        write_message(&mut wire, &payload).unwrap();

        let mut cursor = io::Cursor::new(wire);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), payload);
        // Clean end of stream, not an error.
        assert_eq!(read_message(&mut cursor).unwrap(), None);
    }

    #[test]
    fn an_oversized_length_prefix_is_refused_without_allocating() {
        let mut wire = Vec::new();
        put_u32(&mut wire, (MAX_MESSAGE_LEN + 1) as u32);

        let mut cursor = io::Cursor::new(wire);
        let err = read_message(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_zero_length_message_is_refused() {
        let mut cursor = io::Cursor::new(vec![0, 0, 0, 0]);
        assert!(read_message(&mut cursor).is_err());
    }
}
