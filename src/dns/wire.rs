//! Minimal DNS wire-format reading and response synthesis.
//!
//! The hot paths (cache hit, blocklist hit, static host, forward upstream)
//! only need the question section and a handful of header bits. Running
//! every query through `hickory_proto`'s full `Message::from_vec` ->
//! `Message::to_vec` round trip allocated a `Name`, a `Query`, and a
//! `Vec<Record>` per query just to re-emit bytes that were largely a copy of
//! the input. This module reads the question in place and builds responses by
//! copying the request's own header and question bytes.
//!
//! `hickory_proto` is still used for anything that has to understand records
//! (upstream responses, TTL extraction, negative-caching SOA lookup).

use std::net::Ipv4Addr;
use std::ops::Range;

use hickory_proto::rr::{DNSClass, RecordType};

use super::inline_name::MAX_NAME_LEN;

/// Longest possible encoded qname (255 bytes) plus QTYPE/QCLASS.
const MAX_QUESTION_LEN: usize = 259;

#[derive(Clone)]
pub struct QuestionKey {
    len: u16,
    bytes: [u8; MAX_QUESTION_LEN],
}

impl QuestionKey {
    pub fn from_wire(wire: &[u8]) -> Option<Self> {
        let span = question_span(wire)?;
        let question = wire.get(span)?;
        if question.len() > MAX_QUESTION_LEN {
            return None;
        }
        let mut bytes = [0; MAX_QUESTION_LEN];
        bytes[..question.len()].copy_from_slice(question);
        Some(Self {
            len: question.len() as u16,
            bytes,
        })
    }

    pub fn matches(&self, wire: &[u8]) -> bool {
        question_span(wire)
            .is_some_and(|span| questions_match(&wire[span], &self.bytes[..usize::from(self.len)]))
    }
}

/// Fixed DNS header size (RFC 1035 4.1.1).
pub const HEADER_LEN: usize = 12;

/// EDNS(0) pseudo-record type (RFC 6891).
const OPT_RECORD_TYPE: u16 = 41;

/// DO (DNSSEC OK) bit, the top bit of the OPT record's TTL field.
const DNSSEC_OK_BIT: u32 = 1 << 15;

/// EDNS payload size advertised on synthesized responses that answer a query
/// which itself carried an OPT record. 1232 is the widely-deployed safe value
/// (the DNS Flag Day 2020 recommendation); responses built here are tiny
/// either way, so this only has to be a sane advertisement, not a tuned one.
const EDNS_PAYLOAD_SIZE: u16 = 1232;

/// RCODEs this module needs to set on synthesized responses.
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

/// A query's question section and the header bits needed to answer it, read
/// in place from the request bytes. The qname is written (lowercased) into a
/// caller-owned buffer so parsing allocates nothing at all.
pub struct ParsedQuery {
    pub id: u16,
    pub opcode: u8,
    pub recursion_desired: bool,
    /// Length of the lowercased qname in the caller's buffer.
    pub name_len: usize,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    /// Byte range of the question section within the request.
    pub question: Range<usize>,
    /// Whether the query carried an EDNS OPT record, and if so whether its
    /// DO bit was set. Part of the cache key: a DNSSEC-aware client and a
    /// plain one must not be served each other's answers.
    pub has_opt: bool,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
}

fn u16_at(raw: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*raw.get(at)?, *raw.get(at + 1)?]))
}

/// Reads `raw`'s question section, writing the lowercased qname into
/// `name_buf` in canonical trailing-dot form (the root is just `.`).
///
/// Returns `None` for anything this server won't answer from the fast path:
/// a truncated header, a QDCOUNT other than 1, a malformed or over-long
/// name, or a compression pointer in the question (which cannot point at
/// anything that precedes it, so it is always malformed).
pub fn parse_query(raw: &[u8], name_buf: &mut [u8; MAX_NAME_LEN]) -> Option<ParsedQuery> {
    if raw.len() < HEADER_LEN {
        return None;
    }
    // QR must be clear: this is a query, not a response.
    if raw[2] & 0x80 != 0 {
        return None;
    }
    if u16_at(raw, 4)? != 1 {
        return None;
    }

    let mut at = HEADER_LEN;
    let mut name_len = 0usize;
    loop {
        let label_len = *raw.get(at)? as usize;
        if label_len & 0xc0 != 0 {
            return None; // compression pointer or reserved label type
        }
        at += 1;
        if label_len == 0 {
            break;
        }
        let label = raw.get(at..at + label_len)?;
        // +1 for the dot that follows every label, including the last.
        if name_len + label_len + 1 > MAX_NAME_LEN {
            return None;
        }
        name_buf[name_len..name_len + label_len].copy_from_slice(label);
        name_buf[name_len..name_len + label_len].make_ascii_lowercase();
        name_len += label_len;
        name_buf[name_len] = b'.';
        name_len += 1;
        at += label_len;
    }
    if name_len == 0 {
        name_buf[0] = b'.';
        name_len = 1;
    }

    let qtype = u16_at(raw, at)?;
    let qclass = u16_at(raw, at + 2)?;
    let question = HEADER_LEN..at + 4;
    if question.end > raw.len() {
        return None;
    }

    let (has_opt, dnssec_ok) = find_opt(raw, question.end).unwrap_or((false, false));

    Some(ParsedQuery {
        id: u16::from_be_bytes([raw[0], raw[1]]),
        opcode: (raw[2] >> 3) & 0x0f,
        recursion_desired: raw[2] & 0x01 != 0,
        name_len,
        qtype: RecordType::from(qtype),
        qclass: DNSClass::from(qclass),
        question,
        has_opt,
        dnssec_ok,
        checking_disabled: raw[3] & 0x10 != 0,
    })
}

/// Skips a (possibly compressed) name starting at `at`, returning the offset
/// just past it.
fn skip_name(raw: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *raw.get(at)? as usize;
        if len & 0xc0 == 0xc0 {
            // A pointer always ends the name, and is two bytes wide.
            return Some(at + 2).filter(|end| *end <= raw.len());
        }
        if len & 0xc0 != 0 {
            return None;
        }
        at += 1 + len;
        if len == 0 {
            return Some(at).filter(|end| *end <= raw.len());
        }
    }
}

/// Walks the records after the question looking for an EDNS OPT record,
/// returning whether one was present and whether its DO bit was set.
fn find_opt(raw: &[u8], mut at: usize) -> Option<(bool, bool)> {
    let counts = [u16_at(raw, 6)?, u16_at(raw, 8)?, u16_at(raw, 10)?];
    for (section, count) in counts.iter().enumerate() {
        for _ in 0..*count {
            at = skip_name(raw, at)?;
            let rtype = u16_at(raw, at)?;
            let ttl_at = at + 4;
            let rdlen = u16_at(raw, at + 8)? as usize;
            // OPT is only meaningful in the additional section (index 2).
            if section == 2 && rtype == OPT_RECORD_TYPE {
                let ttl = u32::from_be_bytes([
                    *raw.get(ttl_at)?,
                    *raw.get(ttl_at + 1)?,
                    *raw.get(ttl_at + 2)?,
                    *raw.get(ttl_at + 3)?,
                ]);
                return Some((true, ttl & DNSSEC_OK_BIT != 0));
            }
            at = at + 10 + rdlen;
            if at > raw.len() {
                return None;
            }
        }
    }
    Some((false, false))
}

/// Overwrites the message ID in an already-encoded message. Serving a cached
/// or coalesced response is otherwise byte-identical, so this is the only
/// edit that response needs.
pub fn set_id(wire: &mut [u8], id: u16) {
    if wire.len() >= 2 {
        wire[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// Byte range of `raw`'s question section, for comparing a response's
/// question against the query that asked it.
pub fn question_span(raw: &[u8]) -> Option<Range<usize>> {
    if raw.len() < HEADER_LEN || u16_at(raw, 4)? != 1 {
        return None;
    }
    let end = skip_name(raw, HEADER_LEN)?;
    let question = HEADER_LEN..end + 4;
    (question.end <= raw.len()).then_some(question)
}

/// Compares two question sections for equality, case-insensitively (a
/// resolver may echo back a differently-cased qname, e.g. under 0x20
/// randomization).
pub fn questions_match(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Ages every ordinary resource-record TTL in an encoded DNS response in
/// place. OPT's 32-bit field is extended-RCODE/version/flags, not a TTL, so
/// it is deliberately skipped.
///
/// Returns `false` if the message is malformed. Callers may still serve the
/// original bytes; they just cannot safely age them.
pub fn age_ttls(wire: &mut [u8], elapsed_secs: u32, force_zero: bool) -> bool {
    if wire.len() < HEADER_LEN {
        return false;
    }
    let questions = match u16_at(wire, 4) {
        Some(value) => value,
        None => return false,
    };
    let records = match (u16_at(wire, 6), u16_at(wire, 8), u16_at(wire, 10)) {
        (Some(a), Some(n), Some(r)) => usize::from(a) + usize::from(n) + usize::from(r),
        _ => return false,
    };

    let mut at = HEADER_LEN;
    for _ in 0..questions {
        let Some(end) = skip_name(wire, at) else {
            return false;
        };
        at = end + 4;
        if at > wire.len() {
            return false;
        }
    }
    for _ in 0..records {
        let Some(end) = skip_name(wire, at) else {
            return false;
        };
        at = end;
        let Some(record_type) = u16_at(wire, at) else {
            return false;
        };
        let ttl_at = at + 4;
        let Some(ttl_bytes) = wire.get(ttl_at..ttl_at + 4) else {
            return false;
        };
        let ttl = u32::from_be_bytes(ttl_bytes.try_into().expect("slice is exactly four bytes"));
        if record_type != OPT_RECORD_TYPE {
            let aged = if force_zero {
                0
            } else {
                ttl.saturating_sub(elapsed_secs)
            };
            wire[ttl_at..ttl_at + 4].copy_from_slice(&aged.to_be_bytes());
        }
        let Some(rdlen) = u16_at(wire, at + 8) else {
            return false;
        };
        at += 10 + usize::from(rdlen);
        if at > wire.len() {
            return false;
        }
    }
    true
}

/// Builds a response to `raw` by copying its header and question, with no
/// parse/re-encode round trip.
///
/// `answer` adds a single A record pointing at the question's name (via a
/// compression pointer to offset 12, where the question always starts).
/// An OPT record is echoed back when the query carried one, as RFC 6891
/// requires.
pub fn synthesize(
    raw: &[u8],
    query: &ParsedQuery,
    rcode: u8,
    answer: Option<(Ipv4Addr, u32)>,
) -> Vec<u8> {
    let question = &raw[query.question.clone()];
    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + 16 + 11);

    out.extend_from_slice(&query.id.to_be_bytes());
    // QR set, opcode preserved, RD echoed back.
    out.push(0x80 | (query.opcode << 3) | u8::from(query.recursion_desired));
    // RA set (this is a recursive resolver), Z/AD/CD clear, RCODE as given.
    out.push(0x80 | (u8::from(query.checking_disabled) << 4) | (rcode & 0x0f));
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&u16::from(query.has_opt).to_be_bytes()); // ARCOUNT
    out.extend_from_slice(question);

    if let Some((ip, ttl)) = answer {
        // Pointer to the qname at offset 12 rather than repeating it.
        out.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
        out.extend_from_slice(&u16::from(RecordType::A).to_be_bytes());
        out.extend_from_slice(&u16::from(DNSClass::IN).to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }

    if query.has_opt {
        out.push(0); // root name
        out.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
        out.extend_from_slice(&EDNS_PAYLOAD_SIZE.to_be_bytes());
        let ttl = if query.dnssec_ok { DNSSEC_OK_BIT } else { 0 };
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    }

    out
}

/// Last-resort response for a request too malformed to read a question from:
/// echo whatever ID is there (or zero) with the given RCODE and nothing else.
pub fn bare_error(raw: &[u8], rcode: u8) -> Vec<u8> {
    let id = raw
        .get(0..2)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let opcode = raw.get(2).map_or(0, |b| (b >> 3) & 0x0f);
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&id.to_be_bytes());
    out.push(0x80 | (opcode << 3));
    out.push(0x80 | (rcode & 0x0f));
    out.extend_from_slice(&[0; 8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};

    fn query(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = id;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        message.to_vec().unwrap()
    }

    #[test]
    fn parses_question_without_allocating_or_losing_case() {
        let wire = query("MiXeD.Example.COM", RecordType::AAAA, 0x1234);
        let mut name = [0; MAX_NAME_LEN];
        let parsed = parse_query(&wire, &mut name).unwrap();
        assert_eq!(&name[..parsed.name_len], b"mixed.example.com.");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.qtype, RecordType::AAAA);
        assert_eq!(parsed.qclass, DNSClass::IN);
        assert!(parsed.recursion_desired);
        assert!(!parsed.dnssec_ok);
    }

    #[test]
    fn parses_edns_dnssec_ok_bit() {
        let mut wire = query("dnssec.example", RecordType::A, 3);
        wire[10..12].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        let mut name = [0; MAX_NAME_LEN];
        let parsed = parse_query(&wire, &mut name).unwrap();
        assert!(parsed.has_opt);
        assert!(parsed.dnssec_ok);
    }

    #[test]
    fn synthesized_nxdomain_is_a_valid_response_with_original_question() {
        let request = query("blocked.example", RecordType::A, 7);
        let mut name = [0; MAX_NAME_LEN];
        let parsed = parse_query(&request, &mut name).unwrap();
        let response = synthesize(&request, &parsed, RCODE_NXDOMAIN, None);
        let decoded = Message::from_vec(&response).unwrap();
        assert_eq!(decoded.metadata.id, 7);
        assert_eq!(decoded.metadata.response_code, ResponseCode::NXDomain);
        assert!(decoded.metadata.recursion_available);
        assert_eq!(
            decoded.queries[0].name,
            Name::from_ascii("blocked.example.").unwrap()
        );
        assert!(decoded.answers.is_empty());
    }

    #[test]
    fn synthesized_a_answer_uses_question_pointer_and_round_trips() {
        let request = query("nas.home", RecordType::A, 9);
        let mut name = [0; MAX_NAME_LEN];
        let parsed = parse_query(&request, &mut name).unwrap();
        let response = synthesize(
            &request,
            &parsed,
            RCODE_NOERROR,
            Some((Ipv4Addr::new(10, 0, 0, 2), 60)),
        );
        let decoded = Message::from_vec(&response).unwrap();
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].ttl, 60);
        assert!(matches!(decoded.answers[0].data, RData::A(_)));
        // NAME pointer is immediately after the copied question.
        assert_eq!(
            &response[parsed.question.end..parsed.question.end + 2],
            &[0xc0, HEADER_LEN as u8]
        );
    }

    #[test]
    fn ages_resource_record_ttls_in_place() {
        let request = query("aged.example", RecordType::A, 11);
        let mut name = [0; MAX_NAME_LEN];
        let parsed = parse_query(&request, &mut name).unwrap();
        let mut response = synthesize(
            &request,
            &parsed,
            RCODE_NOERROR,
            Some((Ipv4Addr::new(1, 1, 1, 1), 60)),
        );

        assert!(age_ttls(&mut response, 17, false));
        assert_eq!(Message::from_vec(&response).unwrap().answers[0].ttl, 43);
        assert!(age_ttls(&mut response, 0, true));
        assert_eq!(Message::from_vec(&response).unwrap().answers[0].ttl, 0);
    }

    #[test]
    fn rejects_multiple_questions_and_compressed_question_names() {
        let mut multiple = query("one.example", RecordType::A, 1);
        multiple[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(parse_query(&multiple, &mut [0; MAX_NAME_LEN]).is_none());

        let mut compressed = query("one.example", RecordType::A, 1);
        compressed[HEADER_LEN] = 0xc0;
        assert!(parse_query(&compressed, &mut [0; MAX_NAME_LEN]).is_none());
    }

    #[test]
    fn question_comparison_ignores_0x20_case_randomization() {
        let lower = query("case.example", RecordType::A, 1);
        let upper = query("CASE.EXAMPLE", RecordType::A, 2);
        let a = question_span(&lower).unwrap();
        let b = question_span(&upper).unwrap();
        assert!(questions_match(&lower[a], &upper[b]));
    }
}
