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

use super::get_timestamp_sec;
use proto::observe::LogItem;
use tokio::sync::broadcast::{self, Receiver, Sender};

/// Capacity of the per-channel broadcast ring and of the per-subscriber mpsc
/// that drains it (see `spawn_log_forwarder`). Kept on a power of two so the
/// broadcast doesn't silently round it up, and shared so the mpsc never
/// becomes the binding constraint that forces the receiver to lag before the
/// ring is actually full.
pub(crate) const LOG_STREAM_CAPACITY: usize = 64;

/// Abstraction Layer for one log generating entity
/// LogChannel provides channels between Log producers and log consumers
#[derive(Clone, Debug)]
pub struct LogChannel {
    /// The human readable (public) name for this log channel.
    pub name: String,
    tx: Sender<LogItem>,
}

impl LogChannel {
    /// Constructor creating the channel for log communication
    pub fn new(name: String) -> LogChannel {
        let (tx, _) = broadcast::channel(LOG_STREAM_CAPACITY);
        LogChannel { name, tx }
    }

    /// Getter for consumer channel
    pub fn subscribe(&self) -> Receiver<LogItem> {
        self.tx.subscribe()
    }

    /// Borrows the producer side of the broadcast. Used by the
    /// `MakeWriter for LogChannel` impl in `broadcast_writer.rs` so the
    /// per-event `BroadcastWriter` doesn't have to clone a `Sender` on
    /// each event. `Sender::receiver_count()` and the rest of the surface
    /// the writer needs are all callable through `&Sender`.
    pub(crate) fn sender(&self) -> &Sender<LogItem> {
        &self.tx
    }

    /// Wrapper that sends a log line to the channel
    pub fn send(&self, line: String) {
        // send returns an Err if there are no receivers. We ignore that.
        let _ = self.tx.send(LogItem {
            channel: self.name.clone(),
            line,
            // TODO: milliseconds type in protobuf requires 128bit type
            timestamp: get_timestamp_sec(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ringbuffer_queue() {
        let channel = LogChannel::new("Test".into());
        let mut rx = channel.subscribe();

        channel.send("hello".into());
        channel.send("aurae".into());
        channel.send("bye".into());

        let cur_item = rx.recv().await.ok();
        assert!(cur_item.is_some());
        assert_eq!(cur_item.unwrap().line, "hello".to_string());

        let cur_item = rx.recv().await.ok();
        assert!(cur_item.is_some());
        assert_eq!(cur_item.unwrap().line, "aurae".to_string());

        let cur_item = rx.recv().await.ok();
        assert!(cur_item.is_some());
        assert_eq!(cur_item.unwrap().line, "bye".to_string());
    }
}
