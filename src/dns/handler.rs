use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, A};
use hickory_proto::rr::{RData, Record, RecordType};
use tracing::{debug, warn};

use crate::config::{BlockMode, StaticHost};
use crate::state::AppState;
use crate::util::normalize_name;

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
            let resp = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr);
            return resp.to_vec().unwrap_or_default();
        }
    };

    let response = resolve(state, &request).await;
    response.to_vec().unwrap_or_else(|err| {
        warn!(error = %err, "failed to encode DNS response, returning SERVFAIL");
        Message::error_msg(
            request.metadata.id,
            request.metadata.op_code,
            ResponseCode::ServFail,
        )
        .to_vec()
        .unwrap_or_default()
    })
}

async fn resolve(state: &AppState, request: &Message) -> Message {
    if request.queries.len() != 1 {
        return Message::error_msg(
            request.metadata.id,
            request.metadata.op_code,
            ResponseCode::FormErr,
        );
    }
    let question = &request.queries[0];

    let qname = normalize_name(&question.name.to_ascii());
    let qtype = question.query_type;
    let qclass = question.query_class;

    if let Some(host) = state.static_hosts.get(&qname) {
        return static_response(request, question, host);
    }

    if let Some(mut cached) = state.cache.get(&qname, qtype, qclass) {
        cached.metadata.id = request.metadata.id;
        return cached;
    }

    if state.blocklist.load().contains(&qname) {
        return blocked_response(state, request, question);
    }

    match state.upstreams.resolve(request).await {
        Ok(response) => {
            state.cache.insert(&qname, qtype, qclass, response.clone());
            response
        }
        Err(err) => {
            warn!(error = %err, qname = %qname, "upstream resolution failed");
            Message::error_msg(
                request.metadata.id,
                request.metadata.op_code,
                ResponseCode::ServFail,
            )
        }
    }
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
