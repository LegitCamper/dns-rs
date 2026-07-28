use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use tracing::{debug, warn};

use crate::config::{BlockMode, StaticHost};
use crate::dns::upstream::Upstream;
use crate::state::AppState;

/// Parses raw DNS wire bytes, resolves the query against static hosts, the
/// response cache, the blocklist, and finally upstream, and returns the
/// encoded wire-format response ready to send back to the client.
pub async fn handle_query<U: Upstream>(state: &AppState<U>, raw: &[u8]) -> Vec<u8> {
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

async fn resolve<U: Upstream>(state: &AppState<U>, request: &Message) -> Vec<u8> {
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
        debug!(%qname, ?qtype, "cache hit");
        if wire.len() >= 2 {
            wire[0..2].copy_from_slice(&id.to_be_bytes());
        }
        return wire;
    }
    debug!(%qname, ?qtype, "cache miss");

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

async fn fetch_from_upstream<U: Upstream>(
    state: &AppState<U>,
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
            match response.answers.iter().map(|r| r.ttl).min() {
                Some(ttl) if ttl > 0 => {
                    debug!(%qname, ?qtype, ttl, "caching upstream response");
                    state.cache.insert(qname, qtype, qclass, ttl, wire.clone());
                }
                _ => debug!(%qname, ?qtype, "not caching (no TTL-bearing answers)"),
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

/// Answers directly from a configured static host entry. Only A is ever
/// synthesized (no IPv6 support); any other qtype for a static name yields
/// NOERROR/NODATA rather than being forwarded upstream, since overridden
/// names are never meant to leak externally.
fn static_response(request: &Message, question: &Query, host: &StaticHost) -> Message {
    let mut response = base_response(request, question);
    if question.query_type == RecordType::A {
        let name = question.name.clone();
        response.add_answer(Record::from_rdata(name, host.ttl, RData::A(A::from(host.ip))));
    }
    response
}

fn blocked_response<U: Upstream>(state: &AppState<U>, request: &Message, question: &Query) -> Message {
    let mut response = base_response(request, question);

    match state.block_mode {
        BlockMode::Nxdomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        // Only A gets sinkholed (no IPv6 support); AAAA on a blocked domain
        // just comes back NOERROR/NODATA, which blocks it just as well.
        BlockMode::Sinkhole if question.query_type == RecordType::A => {
            let name = question.name.clone();
            response.add_answer(Record::from_rdata(
                name,
                state.sinkhole_ttl,
                RData::A(A::from(state.sinkhole_ip)),
            ));
        }
        BlockMode::Sinkhole => {}
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use hickory_proto::rr::Name;

    use crate::dns::cache::ResponseCache;
    use crate::dns::inflight::InFlightRegistry;
    use crate::dns::test_support::TestUpstream;
    use crate::dns::upstream::{MultiUpstream, Strategy};

    fn build_state<U: Upstream>(upstreams: Vec<U>, strategy: Strategy) -> AppState<U> {
        AppState {
            static_hosts: HashMap::new(),
            blocklist: Arc::new(ArcSwap::from_pointee(HashSet::new())),
            cache: ResponseCache::new(true, 1000),
            in_flight: InFlightRegistry::new(),
            upstreams: MultiUpstream::new(upstreams, strategy),
            block_mode: BlockMode::Nxdomain,
            sinkhole_ip: Ipv4Addr::UNSPECIFIED,
            sinkhole_ttl: 60,
        }
    }

    fn wire_query(domain: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
        msg.to_vec().unwrap()
    }

    fn decode(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).expect("response should be valid wire format")
    }

    fn only_a_ip(msg: &Message) -> Ipv4Addr {
        match &msg.answers[0].data {
            RData::A(a) => a.0,
            other => panic!("expected an A record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn static_host_answers_without_touching_upstream() {
        let never = Arc::new(TestUpstream::answering("never", "9.9.9.9".parse().unwrap()));
        let mut state = build_state(vec![Arc::clone(&never)], Strategy::Sequential);
        state.static_hosts.insert(
            "nas.home.".to_string(),
            StaticHost {
                ip: "192.168.1.10".parse().unwrap(),
                ttl: 60,
            },
        );

        let response = decode(&handle_query(&state, &wire_query("nas.home", RecordType::A, 1)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(only_a_ip(&response), "192.168.1.10".parse::<Ipv4Addr>().unwrap());
        assert_eq!(response.metadata.id, 1);
        assert_eq!(never.calls(), 0, "static host must never reach upstream");
    }

    #[tokio::test]
    async fn blocklist_nxdomain_mode_blocks_without_touching_upstream() {
        let never = Arc::new(TestUpstream::answering("never", "9.9.9.9".parse().unwrap()));
        let mut state = build_state(vec![Arc::clone(&never)], Strategy::Sequential);
        state.blocklist = Arc::new(ArcSwap::from_pointee(HashSet::from(["ads.example.com.".to_string()])));
        state.block_mode = BlockMode::Nxdomain;

        let response = decode(&handle_query(&state, &wire_query("ads.example.com", RecordType::A, 2)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
        assert_eq!(never.calls(), 0);
    }

    #[tokio::test]
    async fn blocklist_sinkhole_mode_returns_configured_ip() {
        let never = Arc::new(TestUpstream::answering("never", "9.9.9.9".parse().unwrap()));
        let mut state = build_state(vec![Arc::clone(&never)], Strategy::Sequential);
        state.blocklist = Arc::new(ArcSwap::from_pointee(HashSet::from(["ads.example.com.".to_string()])));
        state.block_mode = BlockMode::Sinkhole;
        state.sinkhole_ip = "0.0.0.0".parse().unwrap();

        let response = decode(&handle_query(&state, &wire_query("ads.example.com", RecordType::A, 3)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(only_a_ip(&response), Ipv4Addr::UNSPECIFIED);
        assert_eq!(never.calls(), 0);
    }

    #[tokio::test]
    async fn upstream_miss_answers_correctly_and_populates_the_cache() {
        let upstream = Arc::new(TestUpstream::answering("real", "5.6.7.8".parse().unwrap()));
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let first = decode(&handle_query(&state, &wire_query("example.com", RecordType::A, 10)).await);
        assert_eq!(only_a_ip(&first), "5.6.7.8".parse::<Ipv4Addr>().unwrap());
        assert_eq!(upstream.calls(), 1);

        // Same query again: should come from cache, not hit upstream a second time.
        let second = decode(&handle_query(&state, &wire_query("example.com", RecordType::A, 11)).await);
        assert_eq!(only_a_ip(&second), "5.6.7.8".parse::<Ipv4Addr>().unwrap());
        assert_eq!(second.metadata.id, 11, "cache hit must carry the new request's ID");
        assert_eq!(upstream.calls(), 1, "second identical query should be served from cache");
    }

    #[tokio::test]
    async fn sequential_fallback_works_through_the_full_handler_path() {
        let bad = Arc::new(TestUpstream::failing("bad"));
        let good = Arc::new(TestUpstream::answering("good", "1.1.1.1".parse().unwrap()));
        let state = build_state(vec![Arc::clone(&bad), Arc::clone(&good)], Strategy::Sequential);

        let response = decode(&handle_query(&state, &wire_query("example.org", RecordType::A, 20)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(only_a_ip(&response), "1.1.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bad.calls(), 1);
        assert_eq!(good.calls(), 1);
    }

    #[tokio::test]
    async fn all_upstreams_failing_returns_servfail_not_silence() {
        let a = Arc::new(TestUpstream::failing("a"));
        let b = Arc::new(TestUpstream::failing("b"));
        let state = build_state(vec![Arc::clone(&a), Arc::clone(&b)], Strategy::Sequential);

        let response = decode(&handle_query(&state, &wire_query("example.net", RecordType::A, 30)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.metadata.id, 30);
    }

    #[tokio::test]
    async fn concurrent_identical_misses_only_hit_upstream_once() {
        let upstream = Arc::new(
            TestUpstream::answering("shared", "2.2.2.2".parse().unwrap()).with_delay(Duration::from_millis(50)),
        );
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let queries: Vec<_> = (0..20)
            .map(|i| wire_query("dedup-check.example.com", RecordType::A, 100 + i))
            .collect();
        let responses = futures_util::future::join_all(queries.iter().map(|q| handle_query(&state, q))).await;

        for (i, resp_bytes) in responses.iter().enumerate() {
            let resp = decode(resp_bytes);
            assert_eq!(only_a_ip(&resp), "2.2.2.2".parse::<Ipv4Addr>().unwrap());
            assert_eq!(resp.metadata.id, 100 + i as u16);
        }
        assert_eq!(upstream.calls(), 1, "20 concurrent identical queries should coalesce into 1 upstream call");
    }
}
