use std::sync::Arc;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;
use tracing::{debug, warn};

use crate::config::BlockMode;
use crate::dns::inline_name::MAX_NAME_LEN;
use crate::dns::upstream::Upstream;
use crate::dns::wire::{
    self, ParsedQuery, RCODE_FORMERR, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL,
};
use crate::state::AppState;

/// Parses only the DNS header + question directly from wire bytes, resolves
/// against static hosts, the response cache, the blocklist, and finally the
/// upstream, and returns encoded wire-format bytes ready for the client.
///
/// No `hickory_proto::Message` is built on the client-facing hot path. Cache
/// hits and synthesized answers allocate only their final response `Vec`;
/// forwarded queries retain their original EDNS options byte-for-byte.
pub async fn handle_query<U: Upstream + 'static>(state: &Arc<AppState<U>>, raw: &[u8]) -> Vec<u8> {
    let mut name_buf = [0u8; MAX_NAME_LEN];
    let Some(query) = wire::parse_query(raw, &mut name_buf) else {
        debug!("failed to parse incoming DNS question");
        return wire::bare_error(raw, RCODE_FORMERR);
    };
    let qname = &name_buf[..query.name_len];
    resolve(state, raw, &query, qname).await
}

async fn resolve<U: Upstream + 'static>(
    state: &Arc<AppState<U>>,
    raw: &[u8],
    query: &ParsedQuery,
    qname: &[u8],
) -> Vec<u8> {
    // DO and CD change the answer's DNSSEC semantics, so both belong in the
    // cache/in-flight identity. This fixes the old `(qtype,qclass,qname)`
    // cache serving a plain answer to a DNSSEC-aware query or vice versa.
    let cache_flags = u8::from(query.dnssec_ok) | (u8::from(query.checking_disabled) << 1);
    let qname_str = std::str::from_utf8(qname).ok();

    if let Some(host) = qname_str.and_then(|name| state.static_hosts.get(name)) {
        let answer =
            (query.qtype == hickory_proto::rr::RecordType::A).then_some((host.ip, host.ttl));
        return wire::synthesize(raw, query, RCODE_NOERROR, answer);
    }

    if let Some((mut cached, should_refresh)) =
        state
            .cache
            .get_with_flags(qname, query.qtype, query.qclass, cache_flags)
    {
        debug!(qname = %String::from_utf8_lossy(qname), qtype = ?query.qtype, "cache hit");
        // A name can become blocked while an older allowed answer is still
        // cached. Preserve cache-until-expiry behavior, but don't refresh
        // that answer and keep bypassing the newer blocklist forever.
        if should_refresh && state.blocklist.load().contains_bytes(qname) {
            state.cache.release_refresh_claim_with_flags(
                qname,
                query.qtype,
                query.qclass,
                cache_flags,
            );
        } else if should_refresh {
            // This is the only request-byte copy on a cache hit, and only in
            // the final 10% of its TTL. The client still receives the cached
            // response immediately while this refresh runs in the background.
            let refresh_state = Arc::clone(state);
            let refresh_raw = raw.to_vec();
            let refresh_name = qname.to_vec();
            let qtype = query.qtype;
            let qclass = query.qclass;
            tokio::spawn(async move {
                let fetch_state = Arc::clone(&refresh_state);
                let cache_name = refresh_name.clone();
                refresh_state
                    .in_flight
                    .dedup_with_flags(
                        &refresh_name,
                        qtype,
                        qclass,
                        cache_flags,
                        move || async move {
                            fetch_from_upstream(
                                &fetch_state,
                                &refresh_raw,
                                &cache_name,
                                qtype,
                                qclass,
                                cache_flags,
                            )
                            .await
                        },
                    )
                    .await;
            });
        }
        wire::set_id(&mut cached, query.id);
        return cached;
    }
    debug!(qname = %String::from_utf8_lossy(qname), qtype = ?query.qtype, "cache miss");

    if state.blocklist.load().contains_bytes(qname) {
        let (rcode, answer) = match state.block_mode {
            BlockMode::Nxdomain => (RCODE_NXDOMAIN, None),
            BlockMode::Sinkhole if query.qtype == hickory_proto::rr::RecordType::A => {
                (RCODE_NOERROR, Some((state.sinkhole_ip, state.sinkhole_ttl)))
            }
            BlockMode::Sinkhole => (RCODE_NOERROR, None),
        };
        return wire::synthesize(raw, query, rcode, answer);
    }

    // Coalesce concurrent identical misses into one upstream fetch; each
    // caller (leader or follower) patches its own request ID below.
    let mut response = state
        .in_flight
        .dedup_with_flags(qname, query.qtype, query.qclass, cache_flags, || async {
            fetch_from_upstream(state, raw, qname, query.qtype, query.qclass, cache_flags).await
        })
        .await;
    wire::set_id(&mut response, query.id);
    response
}

async fn fetch_from_upstream<U: Upstream>(
    state: &AppState<U>,
    request: &[u8],
    qname: &[u8],
    qtype: hickory_proto::rr::RecordType,
    qclass: hickory_proto::rr::DNSClass,
    cache_flags: u8,
) -> Vec<u8> {
    match state.upstreams.resolve_wire(request).await {
        Ok(wire) => {
            // TTL extraction is the only place on the normal forwarded path
            // that needs a structured Message. Upstream validation already
            // happened at the transport boundary; a parse failure here makes
            // the response non-cacheable but still lets the valid wire answer
            // reach the client.
            let ttl = Message::from_vec(&wire).ok().and_then(|response| {
                response
                    .answers
                    .iter()
                    .map(|record| record.ttl)
                    .min()
                    .or_else(|| negative_ttl(&response))
                    .filter(|&ttl| ttl > 0)
            });
            match ttl {
                Some(ttl) => {
                    debug!(qname = %String::from_utf8_lossy(qname), ?qtype, ttl, "caching upstream response");
                    state.cache.insert_with_flags(
                        qname,
                        qtype,
                        qclass,
                        cache_flags,
                        ttl,
                        wire.clone(),
                    );
                }
                None => {
                    state
                        .cache
                        .release_refresh_claim_with_flags(qname, qtype, qclass, cache_flags);
                    debug!(qname = %String::from_utf8_lossy(qname), ?qtype, "not caching (no TTL-bearing answers, and no SOA to bound a negative cache)");
                }
            }
            wire
        }
        Err(err) => {
            state
                .cache
                .release_refresh_claim_with_flags(qname, qtype, qclass, cache_flags);
            warn!(error = format!("{err:#}"), qname = %String::from_utf8_lossy(qname), "upstream resolution failed");
            let mut name_buf = [0u8; MAX_NAME_LEN];
            wire::parse_query(request, &mut name_buf).map_or_else(
                || wire::bare_error(request, RCODE_SERVFAIL),
                |query| wire::synthesize(request, &query, RCODE_SERVFAIL, None),
            )
        }
    }
}

/// RFC 2308 negative caching: NXDOMAIN or NODATA is cacheable only if the
/// upstream's authority section has an SOA, using min(SOA TTL, SOA MINIMUM).
/// No SOA means no bound on how long the absence holds, so don't cache it.
fn negative_ttl(response: &Message) -> Option<u32> {
    let is_negative = response.metadata.response_code == ResponseCode::NXDomain
        || (response.metadata.response_code == ResponseCode::NoError
            && response.answers.is_empty());
    if !is_negative {
        return None;
    }
    response
        .authorities
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, Record, RecordType};

    use crate::config::StaticHost;
    use crate::dns::cache::ResponseCache;
    use crate::dns::inflight::InFlightRegistry;
    use crate::dns::test_support::TestUpstream;
    use crate::dns::upstream::{MultiUpstream, Strategy};

    fn build_state<U: Upstream>(upstreams: Vec<U>, strategy: Strategy) -> Arc<AppState<U>> {
        Arc::new(AppState {
            static_hosts: rustc_hash::FxHashMap::default(),
            blocklist: Arc::new(ArcSwap::from_pointee(crate::blocklist::DomainIndex::new())),
            cache: Arc::new(ResponseCache::new(true, 65536)),
            in_flight: InFlightRegistry::new(),
            upstreams: MultiUpstream::new(upstreams, strategy),
            block_mode: BlockMode::Nxdomain,
            sinkhole_ip: Ipv4Addr::UNSPECIFIED,
            sinkhole_ttl: 60,
        })
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
        Arc::get_mut(&mut state).unwrap().static_hosts.insert(
            "nas.home.".to_string(),
            StaticHost {
                ip: "192.168.1.10".parse().unwrap(),
                ttl: 60,
            },
        );

        let response =
            decode(&handle_query(&state, &wire_query("nas.home", RecordType::A, 1)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            only_a_ip(&response),
            "192.168.1.10".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(response.metadata.id, 1);
        assert_eq!(never.calls(), 0, "static host must never reach upstream");
    }

    #[tokio::test]
    async fn blocklist_nxdomain_mode_blocks_without_touching_upstream() {
        let never = Arc::new(TestUpstream::answering("never", "9.9.9.9".parse().unwrap()));
        let mut state = build_state(vec![Arc::clone(&never)], Strategy::Sequential);
        Arc::get_mut(&mut state).unwrap().blocklist = Arc::new(ArcSwap::from_pointee(
            ["ads.example.com.".to_string()].into_iter().collect(),
        ));
        Arc::get_mut(&mut state).unwrap().block_mode = BlockMode::Nxdomain;

        let response =
            decode(&handle_query(&state, &wire_query("ads.example.com", RecordType::A, 2)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
        assert_eq!(never.calls(), 0);
    }

    #[tokio::test]
    async fn blocklist_sinkhole_mode_returns_configured_ip() {
        let never = Arc::new(TestUpstream::answering("never", "9.9.9.9".parse().unwrap()));
        let mut state = build_state(vec![Arc::clone(&never)], Strategy::Sequential);
        Arc::get_mut(&mut state).unwrap().blocklist = Arc::new(ArcSwap::from_pointee(
            ["ads.example.com.".to_string()].into_iter().collect(),
        ));
        Arc::get_mut(&mut state).unwrap().block_mode = BlockMode::Sinkhole;
        Arc::get_mut(&mut state).unwrap().sinkhole_ip = "0.0.0.0".parse().unwrap();

        let response =
            decode(&handle_query(&state, &wire_query("ads.example.com", RecordType::A, 3)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(only_a_ip(&response), Ipv4Addr::UNSPECIFIED);
        assert_eq!(never.calls(), 0);
    }

    #[tokio::test]
    async fn upstream_miss_answers_correctly_and_populates_the_cache() {
        let upstream = Arc::new(TestUpstream::answering("real", "5.6.7.8".parse().unwrap()));
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let first =
            decode(&handle_query(&state, &wire_query("example.com", RecordType::A, 10)).await);
        assert_eq!(only_a_ip(&first), "5.6.7.8".parse::<Ipv4Addr>().unwrap());
        assert_eq!(upstream.calls(), 1);

        // Same query again: should come from cache, not hit upstream a second time.
        let second =
            decode(&handle_query(&state, &wire_query("example.com", RecordType::A, 11)).await);
        assert_eq!(only_a_ip(&second), "5.6.7.8".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            second.metadata.id, 11,
            "cache hit must carry the new request's ID"
        );
        assert_eq!(
            upstream.calls(),
            1,
            "second identical query should be served from cache"
        );
    }

    #[tokio::test]
    async fn near_expiry_cache_hits_return_immediately_and_trigger_exactly_one_background_refresh()
    {
        let upstream = Arc::new(
            TestUpstream::answering("refresh", "5.6.7.8".parse().unwrap())
                .with_delay(Duration::from_millis(100)),
        );
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);
        let query_wire = wire_query("popular.example.com", RecordType::A, 12);
        let query = Message::from_vec(&query_wire).unwrap();
        let mut cached = Message::response(1, OpCode::Query);
        cached.add_query(query.queries[0].clone());
        cached.add_answer(Record::from_rdata(
            query.queries[0].name.clone(),
            100,
            RData::A(A::from("1.2.3.4".parse::<Ipv4Addr>().unwrap())),
        ));
        state.cache.insert(
            "popular.example.com.".to_string(),
            RecordType::A,
            DNSClass::IN,
            100,
            cached.to_vec().unwrap(),
        );
        state.cache.set_remaining_ttl_for_test(
            "popular.example.com.",
            RecordType::A,
            DNSClass::IN,
            Duration::from_secs(9),
        );

        let queries: Vec<_> = (0..20)
            .map(|i| wire_query("popular.example.com", RecordType::A, 200 + i))
            .collect();
        let responses = tokio::time::timeout(
            Duration::from_millis(50),
            futures_util::future::join_all(queries.iter().map(|query| handle_query(&state, query))),
        )
        .await
        .expect("near-expiry cache hits must not wait for the delayed upstream refresh");

        for response in responses {
            assert_eq!(
                only_a_ip(&decode(&response)),
                "1.2.3.4".parse::<Ipv4Addr>().unwrap()
            );
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while upstream.calls() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the claimed refresh should reach upstream in the background");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            upstream.calls(),
            1,
            "many hits in one stale window must trigger exactly one upstream refresh"
        );
    }

    #[tokio::test]
    async fn near_expiry_allowed_answer_is_not_refreshed_after_domain_becomes_blocked() {
        let upstream = Arc::new(TestUpstream::answering(
            "refresh",
            "5.6.7.8".parse().unwrap(),
        ));
        let mut state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);
        let query_wire = wire_query("newly-blocked.example.com", RecordType::A, 12);
        let query = Message::from_vec(&query_wire).unwrap();
        let mut cached = Message::response(1, OpCode::Query);
        cached.add_query(query.queries[0].clone());
        cached.add_answer(Record::from_rdata(
            query.queries[0].name.clone(),
            100,
            RData::A(A::from("1.2.3.4".parse::<Ipv4Addr>().unwrap())),
        ));
        state.cache.insert(
            "newly-blocked.example.com.".to_string(),
            RecordType::A,
            DNSClass::IN,
            100,
            cached.to_vec().unwrap(),
        );
        state.cache.set_remaining_ttl_for_test(
            "newly-blocked.example.com.",
            RecordType::A,
            DNSClass::IN,
            Duration::from_secs(9),
        );
        Arc::get_mut(&mut state).unwrap().blocklist = Arc::new(ArcSwap::from_pointee(
            ["newly-blocked.example.com.".to_string()]
                .into_iter()
                .collect(),
        ));

        let response = decode(&handle_query(&state, &query_wire).await);
        tokio::task::yield_now().await;

        assert_eq!(only_a_ip(&response), "1.2.3.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            upstream.calls(),
            0,
            "a newly-blocked name may finish its existing cache lifetime, but that old allowed answer must never be refreshed"
        );
    }

    #[tokio::test]
    async fn sequential_fallback_works_through_the_full_handler_path() {
        let bad = Arc::new(TestUpstream::failing("bad"));
        let good = Arc::new(TestUpstream::answering("good", "1.1.1.1".parse().unwrap()));
        let state = build_state(
            vec![Arc::clone(&bad), Arc::clone(&good)],
            Strategy::Sequential,
        );

        let response =
            decode(&handle_query(&state, &wire_query("example.org", RecordType::A, 20)).await);

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

        let response =
            decode(&handle_query(&state, &wire_query("example.net", RecordType::A, 30)).await);

        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.metadata.id, 30);
    }

    #[tokio::test]
    async fn dnssec_and_checking_disabled_bits_have_separate_cache_entries() {
        let upstream = Arc::new(TestUpstream::answering("flags", "2.2.2.2".parse().unwrap()));
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let plain = wire_query("flags.example", RecordType::A, 70);
        let mut checking_disabled = wire_query("flags.example", RecordType::A, 71);
        checking_disabled[3] |= 0x10; // CD
        let mut dnssec = wire_query("flags.example", RecordType::A, 72);
        dnssec[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        dnssec.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]); // OPT + DO

        decode(&handle_query(&state, &plain).await);
        decode(&handle_query(&state, &checking_disabled).await);
        decode(&handle_query(&state, &dnssec).await);
        decode(&handle_query(&state, &plain).await);

        assert_eq!(
            upstream.calls(),
            3,
            "plain, CD, and DO queries must not share cached answers"
        );
    }

    #[tokio::test]
    async fn concurrent_identical_misses_only_hit_upstream_once() {
        let upstream = Arc::new(
            TestUpstream::answering("shared", "2.2.2.2".parse().unwrap())
                .with_delay(Duration::from_millis(50)),
        );
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let queries: Vec<_> = (0..20)
            .map(|i| wire_query("dedup-check.example.com", RecordType::A, 100 + i))
            .collect();
        let responses =
            futures_util::future::join_all(queries.iter().map(|q| handle_query(&state, q))).await;

        for (i, resp_bytes) in responses.iter().enumerate() {
            let resp = decode(resp_bytes);
            assert_eq!(only_a_ip(&resp), "2.2.2.2".parse::<Ipv4Addr>().unwrap());
            assert_eq!(resp.metadata.id, 100 + i as u16);
        }
        assert_eq!(
            upstream.calls(),
            1,
            "20 concurrent identical queries should coalesce into 1 upstream call"
        );
    }

    #[tokio::test]
    async fn nxdomain_with_soa_is_negative_cached() {
        let upstream = Arc::new(TestUpstream::nxdomain_with_soa("auth", 3600, 60));
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let first = decode(
            &handle_query(
                &state,
                &wire_query("missing.example.com", RecordType::A, 40),
            )
            .await,
        );
        assert_eq!(first.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(upstream.calls(), 1);

        let second = decode(
            &handle_query(
                &state,
                &wire_query("missing.example.com", RecordType::A, 41),
            )
            .await,
        );
        assert_eq!(second.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(
            second.metadata.id, 41,
            "cache hit must carry the new request's ID"
        );
        assert_eq!(
            upstream.calls(),
            1,
            "second identical query should be served from the negative cache"
        );
    }

    #[tokio::test]
    async fn nodata_with_soa_is_negative_cached() {
        let upstream = Arc::new(TestUpstream::nodata_with_soa("auth", 3600, 60));
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        let first = decode(
            &handle_query(
                &state,
                &wire_query("exists.example.com", RecordType::TXT, 50),
            )
            .await,
        );
        assert_eq!(first.metadata.response_code, ResponseCode::NoError);
        assert!(first.answers.is_empty());
        assert_eq!(upstream.calls(), 1);

        let second = decode(
            &handle_query(
                &state,
                &wire_query("exists.example.com", RecordType::TXT, 51),
            )
            .await,
        );
        assert_eq!(second.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            upstream.calls(),
            1,
            "second identical NODATA query should be served from the negative cache"
        );
    }

    #[tokio::test]
    async fn nxdomain_without_soa_is_never_cached() {
        let upstream = Arc::new(TestUpstream::nxdomain("auth"));
        let state = build_state(vec![Arc::clone(&upstream)], Strategy::Sequential);

        decode(
            &handle_query(
                &state,
                &wire_query("missing.example.org", RecordType::A, 60),
            )
            .await,
        );
        decode(
            &handle_query(
                &state,
                &wire_query("missing.example.org", RecordType::A, 61),
            )
            .await,
        );

        assert_eq!(
            upstream.calls(),
            2,
            "without an SOA there's no bound on the negative TTL, so it must never be cached"
        );
    }

    #[test]
    fn negative_ttl_uses_the_smaller_of_soa_ttl_and_minimum() {
        let mut response = Message::response(1, OpCode::Query);
        response.metadata.response_code = ResponseCode::NXDomain;
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            3600,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                60,
            )),
        ));

        assert_eq!(
            negative_ttl(&response),
            Some(60),
            "MINIMUM (60) is smaller than the SOA record's own TTL (3600)"
        );
    }

    #[test]
    fn negative_ttl_is_none_without_an_soa_record() {
        let mut response = Message::response(1, OpCode::Query);
        response.metadata.response_code = ResponseCode::NXDomain;

        assert_eq!(negative_ttl(&response), None);
    }

    #[test]
    fn negative_ttl_is_none_for_a_positive_response() {
        let mut response = Message::response(1, OpCode::Query);
        response.metadata.response_code = ResponseCode::NoError;
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::from(Ipv4Addr::new(1, 2, 3, 4))),
        ));

        assert_eq!(negative_ttl(&response), None);
    }
}
