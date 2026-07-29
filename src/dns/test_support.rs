//! Shared test-only doubles used by both `dns::upstream`'s and
//! `dns::handler`'s test modules. Never compiled outside `cfg(test)`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record};

use crate::dns::upstream::Upstream;

/// A fake upstream: answers with a fixed IP, a negative response (NXDOMAIN or
/// NODATA, optionally with an SOA authority record), or fails outright —
/// after an optional delay, without touching the network. Counts how many
/// times it was actually queried, so tests can assert fallback/dedup/caching
/// call counts.
pub(crate) struct TestUpstream {
    label: String,
    outcome: Outcome,
    delay: Duration,
    calls: AtomicUsize,
}

enum Outcome {
    Answer(Ipv4Addr),
    Fail,
    Negative { response_code: ResponseCode, soa: Option<(u32, u32)> },
}

impl TestUpstream {
    pub(crate) fn answering(label: &str, ip: Ipv4Addr) -> Self {
        Self {
            label: label.to_string(),
            outcome: Outcome::Answer(ip),
            delay: Duration::ZERO,
            calls: AtomicUsize::new(0),
        }
    }

    pub(crate) fn failing(label: &str) -> Self {
        Self {
            label: label.to_string(),
            outcome: Outcome::Fail,
            delay: Duration::ZERO,
            calls: AtomicUsize::new(0),
        }
    }

    /// NXDOMAIN with no SOA authority record — nothing bounds how long the
    /// non-existence may be assumed to hold, so this must never be cached.
    pub(crate) fn nxdomain(label: &str) -> Self {
        Self::negative(label, ResponseCode::NXDomain, None)
    }

    /// NXDOMAIN carrying the zone's SOA in the authority section, so the
    /// response is negative-cacheable per RFC 2308 using `min(soa_ttl, soa_minimum)`.
    pub(crate) fn nxdomain_with_soa(label: &str, soa_ttl: u32, soa_minimum: u32) -> Self {
        Self::negative(label, ResponseCode::NXDomain, Some((soa_ttl, soa_minimum)))
    }

    /// NODATA: NOERROR with no answers (the name exists, just not for this
    /// qtype), carrying the zone's SOA so it's negative-cacheable.
    pub(crate) fn nodata_with_soa(label: &str, soa_ttl: u32, soa_minimum: u32) -> Self {
        Self::negative(label, ResponseCode::NoError, Some((soa_ttl, soa_minimum)))
    }

    fn negative(label: &str, response_code: ResponseCode, soa: Option<(u32, u32)>) -> Self {
        Self {
            label: label.to_string(),
            outcome: Outcome::Negative { response_code, soa },
            delay: Duration::ZERO,
            calls: AtomicUsize::new(0),
        }
    }

    pub(crate) fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Upstream for TestUpstream {
    fn label(&self) -> &str {
        &self.label
    }

    async fn resolve(&self, query: &Message) -> Result<Message> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.delay > Duration::ZERO {
            tokio::time::sleep(self.delay).await;
        }
        match &self.outcome {
            Outcome::Answer(ip) => {
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.add_query(query.queries[0].clone());
                response.add_answer(Record::from_rdata(query.queries[0].name.clone(), 60, RData::A(A::from(*ip))));
                Ok(response)
            }
            Outcome::Negative { response_code, soa } => {
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.add_query(query.queries[0].clone());
                response.metadata.response_code = *response_code;
                if let Some((soa_ttl, soa_minimum)) = *soa {
                    response.add_authority(Record::from_rdata(
                        Name::from_ascii("example.com.").unwrap(),
                        soa_ttl,
                        RData::SOA(SOA::new(
                            Name::from_ascii("ns1.example.com.").unwrap(),
                            Name::from_ascii("hostmaster.example.com.").unwrap(),
                            1,
                            3600,
                            600,
                            86400,
                            soa_minimum,
                        )),
                    ));
                }
                Ok(response)
            }
            Outcome::Fail => Err(anyhow::anyhow!("{} refused to answer", self.label)),
        }
    }
}
