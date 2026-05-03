/* -------------------------------------------------------------------------- *\
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 * -------------------------------------------------------------------------- *
 * Copyright 2022 - 2024, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */

//! `tracing_subscriber::fmt::MakeWriter` impl for `LogChannel`.
//!
//! Wiring `LogChannel` directly as the writer type means a layer is built
//! by passing the channel through `with_writer`:
//!
//! ```ignore
//! tracing_subscriber::fmt::layer().with_writer(log_channel.clone())
//! ```
//!
//! `MakeWriter::make_writer()` is invoked once per `tracing` event, the
//! returned `BroadcastWriter` accumulates the formatted bytes in a per-event
//! buffer, and `Drop` flushes one `LogItem` into the broadcast.

use super::{get_timestamp_sec, log_channel::LogChannel};
use proto::observe::LogItem;
use std::cell::Cell;
use std::io;
use tokio::sync::broadcast::Sender;
use tracing_subscriber::fmt::MakeWriter;

thread_local! {
    /// Set while a `BroadcastWriter` is flushing a `LogItem` on the current
    /// thread. A tracing event emitted *during* that flush — from any module,
    /// now or in future (e.g. from inside `Sender::send` or a new formatter) —
    /// would otherwise re-enter `BroadcastWriter::drop` and feed back into the
    /// same broadcast. This flag makes that recursion a no-op regardless of the
    /// event's target, so it does not depend on the EnvFilter denylist.
    static IN_BROADCAST_WRITE: Cell<bool> = const { Cell::new(false) };
}

/// RAII guard for `IN_BROADCAST_WRITE`. `enter()` returns `None` if a flush is
/// already in progress on this thread; otherwise it sets the flag and clears it
/// on drop, so the flag is reset even if `Sender::send` panics.
struct ReentryGuard;

impl ReentryGuard {
    fn enter() -> Option<Self> {
        IN_BROADCAST_WRITE.with(|flag| {
            if flag.get() {
                None
            } else {
                flag.set(true);
                Some(ReentryGuard)
            }
        })
    }
}

impl Drop for ReentryGuard {
    fn drop(&mut self) {
        IN_BROADCAST_WRITE.with(|flag| flag.set(false));
    }
}

impl<'a> MakeWriter<'a> for LogChannel {
    type Writer = BroadcastWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        BroadcastWriter {
            tx: self.sender(),
            channel: &self.name,
            buf: Vec::new(),
        }
    }
}

/// Per-event writer. Accumulates bytes and flushes a single `LogItem` on drop.
#[derive(Debug)]
pub struct BroadcastWriter<'a> {
    tx: &'a Sender<LogItem>,
    channel: &'a str,
    buf: Vec<u8>,
}

impl<'a> io::Write for BroadcastWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Drop for BroadcastWriter<'a> {
    fn drop(&mut self) {
        if self.buf.is_empty() || self.tx.receiver_count() == 0 {
            return;
        }
        // Bail if we're already flushing on this thread: a tracing event
        // emitted during the send below would re-enter here and feed back into
        // the broadcast. The guard clears itself when this scope ends.
        let Some(_guard) = ReentryGuard::enter() else {
            return;
        };
        // Reuse the buffer's allocation: fmt::Layer emits one trailing '\n'
        // per event, which we drop in place, and `String::from_utf8` takes
        // ownership of the `Vec` without copying on the (overwhelmingly
        // common) valid-UTF-8 path.
        let mut buf = std::mem::take(&mut self.buf);
        while buf.last() == Some(&b'\n') {
            let _ = buf.pop();
        }
        let line = String::from_utf8(buf).unwrap_or_else(|e| {
            String::from_utf8_lossy(e.as_bytes()).into_owned()
        });
        let _ = self.tx.send(LogItem {
            channel: self.channel.to_owned(),
            line,
            timestamp: get_timestamp_sec(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tokio::sync::broadcast::error::TryRecvError;
    use tracing::subscriber::with_default;
    use tracing_subscriber::{
        EnvFilter, Layer, layer::SubscriberExt, registry,
    };

    /// Build a tracing subscriber that pipes events into `channel` and
    /// applies the given env filter. Mirrors `init::logging::broadcast_layer`
    /// — JSON formatter on top of `LogChannel`'s `MakeWriter`, defaults
    /// otherwise.
    fn build_subscriber(
        channel: &LogChannel,
        filter: &str,
    ) -> impl tracing::Subscriber + Send + Sync {
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(channel.clone())
            .with_filter(EnvFilter::new(filter));
        registry().with(layer)
    }

    /// Drains the broadcast non-blocking and returns all queued LogItems.
    /// Returning the full Vec lets each test assert on exact length, in
    /// addition to whatever per-item invariants it cares about.
    fn drain(
        rx: &mut tokio::sync::broadcast::Receiver<LogItem>,
    ) -> Vec<LogItem> {
        let mut out = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(item) => out.push(item),
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                Err(TryRecvError::Lagged(_)) => {
                    panic!("unexpected Lagged in test")
                }
            }
        }
        out
    }

    /// Parse a LogItem's JSON-formatted line. Panics with a descriptive
    /// message if the line isn't valid JSON, since that would be a regression
    /// in our wire format contract.
    fn parse_line(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("LogItem.line was not valid JSON: {e}\nline: {line:?}")
        })
    }

    /// Sentinel tokens are random UUIDs so the assertion `message == token`
    /// is statistically robust against collisions with formatter output.
    fn token() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn emits_exactly_one_log_item_per_event_as_json() {
        let channel = LogChannel::new("test-channel".into());
        let mut rx = channel.subscribe();
        let subscriber = build_subscriber(&channel, "info");

        let msg_token = token();
        let before = get_timestamp_sec();
        with_default(subscriber, || {
            tracing::info!(target: "auraed::test", "{msg_token}");
        });
        let after = get_timestamp_sec();

        let items = drain(&mut rx);
        assert_eq!(items.len(), 1, "expected exactly one LogItem");
        let item = &items[0];

        // Channel name (proto field) is our contract — must match exactly.
        assert_eq!(item.channel, "test-channel");

        // LogItem.timestamp (proto field) — set by us, in seconds.
        assert!(
            item.timestamp >= before && item.timestamp <= after,
            "timestamp {} not in [{before}, {after}]",
            item.timestamp
        );

        // No embedded newlines (Drop trimmed; fmt::Layer emits one event/line).
        assert!(
            !item.line.contains('\n'),
            "line should not contain embedded newlines: {:?}",
            item.line
        );

        // The wire format is JSON. Parse and assert structured fields.
        let json = parse_line(&item.line);
        assert_eq!(json["level"].as_str(), Some("INFO"), "json: {json}");
        assert_eq!(
            json["target"].as_str(),
            Some("auraed::test"),
            "json: {json}"
        );
        assert_eq!(
            json["fields"]["message"].as_str(),
            Some(msg_token.as_str()),
            "json: {json}"
        );
        // tracing-subscriber's JSON formatter emits its own ISO8601 timestamp
        // distinct from our LogItem.timestamp (which is unix seconds).
        assert!(json.get("timestamp").is_some(), "missing timestamp in {json}");
    }

    #[test]
    fn env_filter_excludes_observe_target() {
        let channel = LogChannel::new("test".into());
        let mut rx = channel.subscribe();
        let subscriber = build_subscriber(&channel, "info,auraed::observe=off");

        let suppressed = token();
        let visible = token();
        with_default(subscriber, || {
            tracing::info!(target: "auraed::observe", "{suppressed}");
            tracing::info!(target: "auraed::cells", "{visible}");
        });

        let items = drain(&mut rx);
        assert_eq!(items.len(), 1, "exactly one event should pass the filter");

        let json = parse_line(&items[0].line);
        assert_eq!(json["target"].as_str(), Some("auraed::cells"));
        assert_eq!(json["fields"]["message"].as_str(), Some(visible.as_str()));
    }

    #[test]
    fn each_event_flushes_a_distinct_log_item() {
        let channel = LogChannel::new("test".into());
        let mut rx = channel.subscribe();
        let subscriber = build_subscriber(&channel, "info");

        let tokens = [token(), token(), token()];
        with_default(subscriber, || {
            for t in &tokens {
                tracing::info!("{t}");
            }
        });

        let items = drain(&mut rx);
        assert_eq!(items.len(), 3, "expected one LogItem per event");

        for (idx, item) in items.iter().enumerate() {
            let json = parse_line(&item.line);
            assert_eq!(
                json["fields"]["message"].as_str(),
                Some(tokens[idx].as_str()),
                "event {idx} message mismatch: {json}"
            );
        }
    }

    #[test]
    fn short_circuits_when_no_subscribers() {
        let channel = LogChannel::new("test".into());
        let subscriber = build_subscriber(&channel, "info");
        assert_eq!(channel.sender().receiver_count(), 0);

        with_default(subscriber, || {
            for _ in 0..50 {
                tracing::info!("no subscribers");
            }
        });

        // Subscribe AFTER the bursts. Per tokio broadcast semantics, a fresh
        // subscriber sees only items sent after subscribe(), so `try_recv`
        // returning Empty proves the writer never emitted any LogItem (it
        // short-circuited on receiver_count == 0).
        let mut rx = channel.subscribe();
        match rx.try_recv() {
            Err(TryRecvError::Empty) => {}
            other => panic!(
                "expected Empty after burst with no subscribers, got: {other:?}"
            ),
        }
    }

    #[test]
    fn drop_writer_with_empty_buffer_does_not_send() {
        // If fmt::Layer ever stops calling write before drop (degenerate path),
        // we shouldn't send a phantom empty LogItem.
        let channel = LogChannel::new("test".into());
        let mut rx = channel.subscribe();
        {
            let _writer = channel.make_writer();
            // No bytes written; drop should be a no-op.
        }
        match rx.try_recv() {
            Err(TryRecvError::Empty) => {}
            other => panic!(
                "empty writer should not produce a LogItem, got: {other:?}"
            ),
        }
    }

    #[test]
    fn reentrant_flush_is_suppressed() {
        use std::io::Write as _;

        let channel = LogChannel::new("test".into());
        let mut rx = channel.subscribe();

        {
            // Stand in for being mid-flush on this thread (what the outer
            // BroadcastWriter::drop holds while calling Sender::send).
            let _outer = ReentryGuard::enter().expect("first enter succeeds");

            // A nested flush — what a tracing event emitted during the send
            // would trigger — must bail without broadcasting.
            let mut nested = channel.make_writer();
            nested.write_all(b"reentrant line").expect("write");
            drop(nested);

            match rx.try_recv() {
                Err(TryRecvError::Empty) => {}
                other => panic!(
                    "reentrant flush must not send a LogItem, got: {other:?}"
                ),
            }
        }

        // Once the guard is released, a normal flush works again.
        let mut writer = channel.make_writer();
        writer.write_all(b"normal line").expect("write");
        drop(writer);

        let item = rx.try_recv().expect("normal flush should send");
        assert_eq!(item.line, "normal line");
    }
}
