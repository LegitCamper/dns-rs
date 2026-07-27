//! Shared test-only doubles used by both `dns::upstream`'s and
//! `dns::handler`'s test modules. Never compiled outside `cfg(test)`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};

use crate::dns::upstream::Upstream;

/// A fake upstream: answers with a fixed IP after an optional delay, or
/// fails, without touching the network. Counts how many times it was
/// actually queried, so tests can assert fallback/dedup call counts.
pub(crate) struct TestUpstream {
    label: String,
    outcome: Outcome,
    delay: Duration,
    calls: AtomicUsize,
}

enum Outcome {
    Answer(Ipv4Addr),
    Fail,
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
        match self.outcome {
            Outcome::Answer(ip) => {
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.add_query(query.queries[0].clone());
                response.add_answer(Record::from_rdata(query.queries[0].name.clone(), 60, RData::A(A::from(ip))));
                Ok(response)
            }
            Outcome::Fail => Err(anyhow::anyhow!("{} refused to answer", self.label)),
        }
    }
}
