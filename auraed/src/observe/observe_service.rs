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

// @todo @krisnova remove this once logging is further along
#![allow(dead_code)]

use super::cgroup_cache;
use super::error::ObserveServiceError;
use super::observed_event_stream::ObservedEventStream;
use super::proc_cache::{ProcCache, ProcfsProcessInfo};
use crate::ebpf::tracepoint::PerfEventBroadcast;
use crate::logging::log_channel::{LOG_STREAM_CAPACITY, LogChannel};
use aurae_ebpf_shared::{ForkedProcess, ProcessExit, Signal};
use cgroup_cache::CgroupCache;
use proto::observe::{
    GetAuraeDaemonLogStreamRequest, GetAuraeDaemonLogStreamResponse,
    GetPosixSignalsStreamRequest, GetPosixSignalsStreamResponse,
    GetSubProcessStreamRequest, GetSubProcessStreamResponse, LogChannelType,
    LogItem, Signal as PosixSignal, WorkloadType, observe_service_server,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, broadcast::Receiver, broadcast::error::RecvError};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, instrument, warn};

#[derive(Debug, Clone)]
pub struct ObserveService {
    aurae_logger: LogChannel,
    cgroup_cache: CgroupCache,
    proc_cache: Option<ProcCache>,
    posix_signals: Option<PerfEventBroadcast<Signal>>,
    sub_process_consumer_list:
        Arc<Mutex<HashMap<i32, HashMap<LogChannelType, LogChannel>>>>,
}

type PerfEvents = (
    Option<PerfEventBroadcast<ForkedProcess>>,
    Option<PerfEventBroadcast<ProcessExit>>,
    Option<PerfEventBroadcast<Signal>>,
);

impl ObserveService {
    pub fn new(aurae_logger: LogChannel, perf_events: PerfEvents) -> Self {
        let proc_cache = match perf_events {
            (Some(f), Some(e), _) => Some(ProcCache::new(
                Duration::from_secs(60),
                Duration::from_secs(60),
                f,
                e,
                ProcfsProcessInfo {},
            )),
            _ => None,
        };
        Self {
            aurae_logger,
            cgroup_cache: CgroupCache::new("/sys/fs/cgroup".into()),
            proc_cache,
            posix_signals: perf_events.2,
            sub_process_consumer_list: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn register_sub_process_channel(
        &self,
        pid: i32,
        channel_type: LogChannelType,
        channel: LogChannel,
    ) -> Result<(), ObserveServiceError> {
        info!("Registering channel for pid {pid} {channel_type:?}");
        let mut consumer_list = self.sub_process_consumer_list.lock().await;
        if consumer_list.get(&pid).is_none() {
            let _ = consumer_list.insert(pid, HashMap::new());
        }
        if consumer_list
            .get(&pid)
            .expect("pid channels")
            .get(&channel_type)
            .is_some()
        {
            return Err(ObserveServiceError::ChannelAlreadyRegistered {
                pid,
                channel_type,
            });
        }
        let _ = consumer_list
            .get_mut(&pid)
            .expect("pid channels")
            .insert(channel_type, channel);
        Ok(())
    }

    pub async fn unregister_sub_process_channel(
        &self,
        pid: i32,
        channel_type: LogChannelType,
    ) -> Result<(), ObserveServiceError> {
        info!("Unregistering for pid {pid} {channel_type:?}");
        let mut consumer_list = self.sub_process_consumer_list.lock().await;
        if let Some(channels) = consumer_list.get_mut(&pid) {
            if channels.remove(&channel_type).is_none() {
                return Err(ObserveServiceError::ChannelNotRegistered {
                    pid,
                    channel_type,
                });
            }
        } else {
            return Err(ObserveServiceError::NoChannelsForPid { pid });
        }
        Ok(())
    }

    #[instrument(skip(self))]
    fn subscribe_posix_signals(
        &self,
        filter: Option<(WorkloadType, String)>,
    ) -> ReceiverStream<Result<GetPosixSignalsStreamResponse, Status>> {
        //TODO map err -> gRPC error status
        let events = ObservedEventStream::new(
            self.posix_signals.as_ref().expect("signals"),
        )
        .filter_by_workload(filter)
        .map_pids(self.proc_cache.as_ref().expect("proc_cache").clone())
        .subscribe(map_get_posix_signals_stream_response);

        ReceiverStream::new(events)
    }

    /// Bridge a broadcast `LogItem` consumer to a gRPC stream. Each item is
    /// wrapped with the caller-supplied envelope. On `RecvError::Lagged` the
    /// broadcast `Receiver` has already dropped the oldest unread items and
    /// auto-recovered to the oldest still-buffered one; the gap is logged
    /// server-side and forwarding continues. We deliberately do not surface
    /// the lag as a `Status` item: tonic ends a server-streaming RPC at the
    /// first `Err(Status)` the stream yields (it becomes the `grpc-status`
    /// trailer), so emitting one would terminate the client's stream rather
    /// than merely signal the gap. The forwarder task exits when the client
    /// disconnects (`tx.send` errors) or all senders are dropped
    /// (`RecvError::Closed`).
    ///
    /// The mpsc is sized to `LOG_STREAM_CAPACITY` to match the broadcast ring.
    /// A broadcast `Receiver` can't backpressure its sender, so a smaller mpsc
    /// would only make the receiver lag (and surface `DataLoss`) before the
    /// ring was actually full; matching the capacities lets a client absorb a
    /// full ring's worth of buffered events before any are dropped.
    fn spawn_log_forwarder<R: Send + 'static>(
        &self,
        mut consumer: Receiver<LogItem>,
        wrap: impl Fn(LogItem) -> R + Send + 'static,
    ) -> ReceiverStream<Result<R, Status>> {
        let (tx, rx) = mpsc::channel::<Result<R, Status>>(LOG_STREAM_CAPACITY);

        // The broadcast layer's EnvFilter excludes events with target
        // `auraed::observe`, so any tracing emitted from inside this task
        // does not feed back into the consumer.
        let _ignored = tokio::spawn(async move {
            loop {
                match consumer.recv().await {
                    Ok(item) => {
                        if tx.send(Ok(wrap(item))).await.is_err() {
                            break; // gRPC client gone
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        // The ring overran a slow consumer. The Receiver has
                        // auto-recovered to the oldest still-buffered item, so
                        // keep forwarding; surfacing an `Err(Status)` here
                        // would end the client's RPC (see method docs). The
                        // `auraed::observe` target is excluded from the
                        // broadcast layer, so this warning does not feed back.
                        warn!("log stream lagged: dropped {n} messages");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

fn map_get_posix_signals_stream_response(
    signal: Signal,
    pid: i32,
) -> GetPosixSignalsStreamResponse {
    GetPosixSignalsStreamResponse {
        signal: Some(PosixSignal { signal: signal.signum, process_id: pid }),
    }
}

#[cfg(test)]
impl ObserveService {
    pub async fn has_sub_process_channel(
        &self,
        pid: i32,
        channel_type: LogChannelType,
    ) -> bool {
        let consumer_list = self.sub_process_consumer_list.lock().await;
        consumer_list
            .get(&pid)
            .and_then(|channels| channels.get(&channel_type))
            .is_some()
    }
}

#[tonic::async_trait]
impl observe_service_server::ObserveService for ObserveService {
    type GetAuraeDaemonLogStreamStream =
        ReceiverStream<Result<GetAuraeDaemonLogStreamResponse, Status>>;

    async fn get_aurae_daemon_log_stream(
        &self,
        _request: Request<GetAuraeDaemonLogStreamRequest>,
    ) -> Result<Response<Self::GetAuraeDaemonLogStreamStream>, Status> {
        let consumer = self.aurae_logger.subscribe();
        Ok(Response::new(self.spawn_log_forwarder(consumer, |item| {
            GetAuraeDaemonLogStreamResponse { item: Some(item) }
        })))
    }

    type GetSubProcessStreamStream =
        ReceiverStream<Result<GetSubProcessStreamResponse, Status>>;

    async fn get_sub_process_stream(
        &self,
        request: Request<GetSubProcessStreamRequest>,
    ) -> Result<Response<Self::GetSubProcessStreamStream>, Status> {
        let GetSubProcessStreamRequest {
            process_id: pid,
            channel_type,
            cell_name: _,
        } = request.into_inner();
        let channel = LogChannelType::try_from(channel_type).map_err(|_| {
            ObserveServiceError::InvalidLogChannelType { channel_type }
        })?;

        debug!("get_sub_process_stream channel={channel:?} pid={pid}");

        let consumer = {
            let mut consumer_list = self.sub_process_consumer_list.lock().await;
            consumer_list
                .get_mut(&pid)
                .ok_or(ObserveServiceError::NoChannelsForPid { pid })?
                .get_mut(&channel)
                .ok_or(ObserveServiceError::ChannelNotRegistered {
                    pid,
                    channel_type: channel,
                })?
                .subscribe()
        };

        Ok(Response::new(self.spawn_log_forwarder(consumer, |item| {
            GetSubProcessStreamResponse { item: Some(item) }
        })))
    }

    type GetPosixSignalsStreamStream =
        ReceiverStream<Result<GetPosixSignalsStreamResponse, Status>>;

    async fn get_posix_signals_stream(
        &self,
        request: Request<GetPosixSignalsStreamRequest>,
    ) -> Result<Response<Self::GetPosixSignalsStreamStream>, Status> {
        if self.posix_signals.is_none() {
            return Err(Status::unimplemented(
                "GetPosixSignalStream is not implemented for nested Aurae daemons",
            ));
        }

        Ok(Response::new(self.subscribe_posix_signals(
            request.into_inner().workload.map(|w| (w.workload_type(), w.id)),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::log_channel::LogChannel;
    use proto::observe::LogChannelType;

    #[tokio::test]
    async fn test_register_sub_process_channel_success() {
        let svc = ObserveService::new(
            LogChannel::new(String::from("auraed")),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .await
            .is_ok()
        );

        svc.sub_process_consumer_list.lock().await.clear();
    }

    #[tokio::test]
    async fn test_register_sub_process_channel_duplicate_error() {
        let svc = ObserveService::new(
            LogChannel::new(String::from("auraed")),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .await
            .is_ok()
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("bar"))
            )
            .await
            .is_err()
        );

        svc.sub_process_consumer_list.lock().await.clear();
    }

    #[tokio::test]
    async fn test_unregister_sub_process_channel_success() {
        let svc = ObserveService::new(
            LogChannel::new(String::from("auraed")),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .await
            .is_ok()
        );
        assert!(
            svc.unregister_sub_process_channel(42, LogChannelType::Stdout)
                .await
                .is_ok()
        );

        svc.sub_process_consumer_list.lock().await.clear();
    }

    #[tokio::test]
    async fn test_unregister_sub_process_channel_no_pid_error() {
        let svc = ObserveService::new(
            LogChannel::new(String::from("auraed")),
            (None, None, None),
        );
        assert!(
            svc.unregister_sub_process_channel(42, LogChannelType::Stdout)
                .await
                .is_err()
        );

        svc.sub_process_consumer_list.lock().await.clear();
    }

    #[tokio::test]
    async fn test_unregister_sub_process_channel_no_channel_type_error() {
        let svc = ObserveService::new(
            LogChannel::new(String::from("auraed")),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .await
            .is_ok()
        );
        assert!(
            svc.unregister_sub_process_channel(42, LogChannelType::Stderr)
                .await
                .is_err()
        );

        svc.sub_process_consumer_list.lock().await.clear();
    }

    /// Parses the index N out of a `"msg NNNN"` log line.
    fn parse_msg_index(line: &str) -> Option<usize> {
        line.strip_prefix("msg ")?.trim().parse().ok()
    }

    /// Bursting more items than the broadcast ringbuffer holds while the
    /// consumer is parked triggers RecvError::Lagged inside the forwarder.
    /// The forwarder must swallow the lag (logging it server-side) and keep
    /// the gRPC stream open, delivering the oldest still-buffered items in
    /// order. It must never yield an `Err(Status)`, which tonic would turn
    /// into the RPC's terminating trailer over the wire.
    #[tokio::test]
    async fn lagged_consumer_skips_dropped_messages_and_continues() {
        use tokio_stream::StreamExt as _;

        let aurae_logger = LogChannel::new("auraed".into());
        let svc = ObserveService::new(aurae_logger.clone(), (None, None, None));

        // Subscribe FIRST (handler captures broadcast::Receiver at sender pos 0).
        let mut stream =
            <ObserveService as observe_service_server::ObserveService>::get_aurae_daemon_log_stream(
                &svc,
                Request::new(GetAuraeDaemonLogStreamRequest { cell_name: None }),
            )
            .await
            .expect("handler returned stream")
            .into_inner();

        // Burst far past whatever the ringbuffer can hold (tokio rounds the
        // requested capacity up to a power of two, so the exact cap is an
        // implementation detail we don't pin here). 1024 messages is enough
        // to overrun any reasonable cap.
        const BURST: usize = 1024;
        for i in 0..BURST {
            aurae_logger.send(format!("msg {i:04}"));
        }

        // The forwarder's first recv() sees Lagged and swallows it, so the
        // first item the client observes is a real LogItem (the oldest item
        // still in the ring) — never an `Err(Status)`, which would end the RPC.
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.next(),
        )
        .await
        .expect("did not receive first item before timeout")
        .expect("stream ended unexpectedly")
        .expect("first item must be Ok; a Status would terminate the RPC");

        let first_line = first.item.expect("LogItem present").line;
        let first_idx = parse_msg_index(&first_line)
            .unwrap_or_else(|| panic!("unexpected line: {first_line:?}"));
        // The front of the burst was dropped; we recovered partway through.
        assert!(
            first_idx > 0 && first_idx < BURST,
            "first surviving index {first_idx} must be in (0, {BURST})"
        );

        // Stream stays open and keeps delivering items contiguously after the
        // dropped prefix.
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.next(),
        )
        .await
        .expect("post-lag item timeout")
        .expect("stream ended unexpectedly")
        .expect("post-lag item should be Ok");

        let next_line = next.item.expect("LogItem present").line;
        let next_idx = parse_msg_index(&next_line)
            .unwrap_or_else(|| panic!("unexpected line: {next_line:?}"));
        assert_eq!(
            next_idx,
            first_idx + 1,
            "items must arrive contiguously after the dropped prefix",
        );
    }
}
