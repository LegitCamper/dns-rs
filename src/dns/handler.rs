use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, A};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use tracing::{debug, warn};

use crate::config::{BlockMode, StaticHost};
use crate::state::AppState;

/// Parses raw DNS wire bytes, resolves the query against static hosts, the
/// response cache, the blocklist, and finally upstream, and returns the
/// encoded wire-format response ready to send back to the client.
pub async fn handle_query(state: &AppState, raw: &[u8]) -> Vec<u8> {
    let request = match Message::from_vec(raw) {
        Ok(m) => m,
        Err(err) => {
            debug!(error = %err, "failed to parse incoming DNS message");
            let id = raw
                .get(0..2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .unwrap_or(0);
            return encode_or_servfail(&Message::error_msg(id, OpCode::Query, ResponseCode::FormErr), id, OpCode::Query);
        }
    };

    resolve(state, &request).await
}

async fn resolve(state: &AppState, request: &Message) -> Vec<u8> {
    let id = request.metadata.id;
    let op_code = request.metadata.op_code;

    if request.queries.len() != 1 {
        return encode_or_servfail(&Message::error_msg(id, op_code, ResponseCode::FormErr), id, op_code);
    }
    let question = &request.queries[0];

    // Wire-parsed names are always fully-qualified, so `to_ascii()` already
    // yields the canonical trailing-dot form; only the case needs normalizing,
    // and doing that in place avoids a second allocation.
    let mut qname = question.name.to_ascii();
    qname.make_ascii_lowercase();
    let qtype = question.query_type;
    let qclass = question.query_class;

    if let Some(host) = state.static_hosts.get(&qname) {
        return encode_or_servfail(&static_response(request, question, host), id, op_code);
    }

    if let Some(mut wire) = state.cache.get(&qname, qtype, qclass) {
        if wire.len() >= 2 {
            wire[0..2].copy_from_slice(&id.to_be_bytes());
        }
        return wire;
    }

    if state.blocklist.load().contains(&qname) {
        return encode_or_servfail(&blocked_response(state, request, question), id, op_code);
    }

    // Coalesce concurrent identical misses into a single upstream fetch;
    // each caller (leader or follower) still patches its own request ID below.
    let cache_key = qname.clone();
    let mut wire = state
        .in_flight
        .dedup(&qname, qtype, qclass, move || async move {
            fetch_from_upstream(state, request, cache_key, qtype, qclass, id, op_code).await
        })
        .await;

    if wire.len() >= 2 {
        wire[0..2].copy_from_slice(&id.to_be_bytes());
    }
    wire
}

async fn fetch_from_upstream(
    state: &AppState,
    request: &Message,
    qname: String,
    qtype: RecordType,
    qclass: DNSClass,
    id: u16,
    op_code: OpCode,
) -> Vec<u8> {
    match state.upstreams.resolve(request).await {
        Ok(response) => {
            let wire = encode_or_servfail(&response, id, op_code);
            if let Some(ttl) = response.answers.iter().map(|r| r.ttl).min() {
                if ttl > 0 {
                    state.cache.insert(qname, qtype, qclass, ttl, wire.clone());
                }
            }
            wire
        }
        Err(err) => {
            warn!(error = %err, qname = %qname, "upstream resolution failed");
            encode_or_servfail(&Message::error_msg(id, op_code, ResponseCode::ServFail), id, op_code)
        }
    }
}

fn encode_or_servfail(message: &Message, request_id: u16, op_code: OpCode) -> Vec<u8> {
    message.to_vec().unwrap_or_else(|err| {
        warn!(error = %err, "failed to encode DNS response, returning SERVFAIL");
        Message::error_msg(request_id, op_code, ResponseCode::ServFail)
            .to_vec()
            .unwrap_or_default()
    })
}

fn base_response(request: &Message, question: &Query) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_query(question.clone());
    response
}

/// Answers directly from a configured static host entry. Only A/AAAA are
/// ever synthesized; any other qtype for a static name yields NOERROR/NODATA
/// rather than being forwarded upstream, since overridden names are never
/// meant to leak externally.
fn static_response(request: &Message, question: &Query, host: &StaticHost) -> Message {
    let mut response = base_response(request, question);
    let name = question.name.clone();
    match question.query_type {
        RecordType::A => {
            for ip in &host.ipv4 {
                response.add_answer(Record::from_rdata(name.clone(), host.ttl, RData::A(A::from(*ip))));
            }
        }
        RecordType::AAAA => {
            for ip in &host.ipv6 {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    host.ttl,
                    RData::AAAA(AAAA::from(*ip)),
                ));
            }
        }
        _ => {}
    }
    response
}

fn blocked_response(state: &AppState, request: &Message, question: &Query) -> Message {
    let mut response = base_response(request, question);

    match state.block_mode {
        BlockMode::Nxdomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockMode::Sinkhole => {
            let name = question.name.clone();
            match question.query_type {
                RecordType::A => {
                    response.add_answer(Record::from_rdata(
                        name,
                        state.sinkhole_ttl,
                        RData::A(A::from(state.sinkhole_ipv4)),
                    ));
                }
                RecordType::AAAA => {
                    response.add_answer(Record::from_rdata(
                        name,
                        state.sinkhole_ttl,
                        RData::AAAA(AAAA::from(state.sinkhole_ipv6)),
                    ));
                }
                _ => {}
            }
        }
    }

    response
}
