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
use crate::logging::log_channel::LogChannel;
use aurae_ebpf_shared::{ForkedProcess, ProcessExit, Signal};
use cgroup_cache::CgroupCache;
use proto::observe::{
    GetAuraeDaemonLogStreamRequest, GetAuraeDaemonLogStreamResponse,
    GetPosixSignalsStreamRequest, GetPosixSignalsStreamResponse,
    GetSubProcessStreamRequest, GetSubProcessStreamResponse, LogChannelType,
    LogItem, Signal as PosixSignal, WorkloadType, observe_service_server,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, instrument};

#[derive(Debug, Clone)]
pub struct ObserveService {
    aurae_logger: Arc<LogChannel>,
    cgroup_cache: Arc<CgroupCache>,
    proc_cache: Option<Arc<ProcCache>>,
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
    pub fn new(aurae_logger: Arc<LogChannel>, perf_events: PerfEvents) -> Self {
        let proc_cache = match perf_events {
            (Some(f), Some(e), _) => Some(Arc::new(ProcCache::new(
                Duration::from_secs(60),
                Duration::from_secs(60),
                f,
                e,
                ProcfsProcessInfo {},
            ))),
            _ => None,
        };
        Self {
            aurae_logger,
            cgroup_cache: Arc::new(CgroupCache::new("/sys/fs/cgroup".into())),
            proc_cache,
            posix_signals: perf_events.2,
            sub_process_consumer_list: Default::default(),
        }
    }

    #[instrument(skip(self, channel))]
    pub fn register_sub_process_channel(
        &self,
        pid: i32,
        channel_type: LogChannelType,
        channel: LogChannel,
    ) -> Result<(), ObserveServiceError> {
        info!("Registering channel for pid {pid} {channel_type:?}");
        let mut consumer_list = self
            .sub_process_consumer_list
            .lock()
            .expect("Failed to lock consumer list");
        let channels = consumer_list.entry(pid).or_default();
        if channels.contains_key(&channel_type) {
            return Err(ObserveServiceError::ChannelAlreadyRegistered {
                pid,
                channel_type,
            });
        }
        let _ = channels.insert(channel_type, channel);
        Ok(())
    }

    #[instrument(skip(self))]
    pub fn unregister_sub_process_channel(
        &self,
        pid: i32,
        channel_type: LogChannelType,
    ) -> Result<(), ObserveServiceError> {
        info!("Unregistering for pid {pid} {channel_type:?}");
        let mut consumer_list = self
            .sub_process_consumer_list
            .lock()
            .expect("Failed to lock consumer list");

        let channels = consumer_list
            .get_mut(&pid)
            .ok_or(ObserveServiceError::NoChannelsForPid { pid })?;

        let _ = channels.remove(&channel_type).ok_or(
            ObserveServiceError::ChannelNotRegistered { pid, channel_type },
        )?;
        Ok(())
    }

    fn get_aurae_daemon_log_stream(&self) -> Receiver<LogItem> {
        self.aurae_logger.subscribe()
    }

    fn get_posix_signals_stream(
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
    pub fn has_sub_process_channel(
        &self,
        pid: i32,
        channel_type: LogChannelType,
    ) -> bool {
        let consumer_list = self
            .sub_process_consumer_list
            .lock()
            .expect("failed to acquire lock");
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

    #[instrument(skip(self))]
    async fn get_aurae_daemon_log_stream(
        &self,
        _request: Request<GetAuraeDaemonLogStreamRequest>,
    ) -> Result<Response<Self::GetAuraeDaemonLogStreamStream>, Status> {
        let (tx, rx) =
            mpsc::channel::<Result<GetAuraeDaemonLogStreamResponse, Status>>(4);
        let mut log_consumer = self.get_aurae_daemon_log_stream();

        // TODO: error handling. Warning: recursively logging if error message is also send to this grpc api endpoint
        //  .. thus disabled logging here.
        let _ignored = tokio::spawn(async move {
            // Log consumer will error if:
            //  the producer is closed (no more logs)
            //  the receiver is lagging
            while let Ok(log_item) = log_consumer.recv().await {
                let resp =
                    GetAuraeDaemonLogStreamResponse { item: Some(log_item) };
                if tx.send(Ok(resp)).await.is_err() {
                    // receiver is gone
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type GetSubProcessStreamStream =
        ReceiverStream<Result<GetSubProcessStreamResponse, Status>>;

    #[instrument(skip(self))]
    async fn get_sub_process_stream(
        &self,
        request: Request<GetSubProcessStreamRequest>,
    ) -> Result<Response<Self::GetSubProcessStreamStream>, Status> {
        let channel = LogChannelType::try_from(request.get_ref().channel_type)
            .map_err(|_| ObserveServiceError::InvalidLogChannelType {
                channel_type: request.get_ref().channel_type,
            })?;
        let pid: i32 = request.get_ref().process_id;

        debug!("Requested Channel {channel:?}");
        debug!("Requested Process ID {pid}");

        let mut log_consumer = {
            let mut consumer_list = self
                .sub_process_consumer_list
                .lock()
                .expect("failed to acquire lock");
            consumer_list
                .get_mut(&pid)
                .ok_or(ObserveServiceError::NoChannelsForPid { pid })?
                .get_mut(&channel)
                .ok_or(ObserveServiceError::ChannelNotRegistered {
                    pid,
                    channel_type: channel,
                })?
                .clone()
        }
        .subscribe();

        let (tx, rx) =
            mpsc::channel::<Result<GetSubProcessStreamResponse, Status>>(1024);

        // TODO: error handling. Warning: recursively logging if error message is also send to this grpc api endpoint
        //  .. thus disabled logging here.
        let _ignored = tokio::spawn(async move {
            // Log consumer will error if:
            //  the producer is closed (no more logs)
            //  the receiver is lagging
            while let Ok(log_item) = log_consumer.recv().await {
                let resp = GetSubProcessStreamResponse { item: Some(log_item) };
                if tx.send(Ok(resp)).await.is_err() {
                    // receiver is gone
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type GetPosixSignalsStreamStream =
        ReceiverStream<Result<GetPosixSignalsStreamResponse, Status>>;

    #[instrument(skip(self))]
    async fn get_posix_signals_stream(
        &self,
        request: Request<GetPosixSignalsStreamRequest>,
    ) -> Result<Response<Self::GetPosixSignalsStreamStream>, Status> {
        if self.posix_signals.is_none() {
            return Err(Status::unimplemented(
                "GetPosixSignalStream is not implemented for nested Aurae daemons",
            ));
        }

        Ok(Response::new(self.get_posix_signals_stream(
            request.into_inner().workload.map(|w| (w.workload_type(), w.id)),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::ObserveService;
    use crate::logging::log_channel::LogChannel;
    use proto::observe::LogChannelType;
    use std::sync::Arc;

    #[test]
    fn test_register_sub_process_channel_success() {
        let svc = ObserveService::new(
            Arc::new(LogChannel::new(String::from("auraed"))),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .is_ok()
        );

        svc.sub_process_consumer_list.lock().unwrap().clear();
    }

    #[test]
    fn test_register_sub_process_channel_duplicate_error() {
        let svc = ObserveService::new(
            Arc::new(LogChannel::new(String::from("auraed"))),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .is_ok()
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("bar"))
            )
            .is_err()
        );

        svc.sub_process_consumer_list.lock().unwrap().clear();
    }

    #[test]
    fn test_unregister_sub_process_channel_success() {
        let svc = ObserveService::new(
            Arc::new(LogChannel::new(String::from("auraed"))),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .is_ok()
        );
        assert!(
            svc.unregister_sub_process_channel(42, LogChannelType::Stdout)
                .is_ok()
        );

        svc.sub_process_consumer_list.lock().unwrap().clear();
    }

    #[test]
    fn test_unregister_sub_process_channel_no_pid_error() {
        let svc = ObserveService::new(
            Arc::new(LogChannel::new(String::from("auraed"))),
            (None, None, None),
        );
        assert!(
            svc.unregister_sub_process_channel(42, LogChannelType::Stdout)
                .is_err()
        );

        svc.sub_process_consumer_list.lock().unwrap().clear();
    }

    #[test]
    fn test_unregister_sub_process_channel_no_channel_type_error() {
        let svc = ObserveService::new(
            Arc::new(LogChannel::new(String::from("auraed"))),
            (None, None, None),
        );
        assert!(
            svc.register_sub_process_channel(
                42,
                LogChannelType::Stdout,
                LogChannel::new(String::from("foo"))
            )
            .is_ok()
        );
        assert!(
            svc.unregister_sub_process_channel(42, LogChannelType::Stderr)
                .is_err()
        );

        svc.sub_process_consumer_list.lock().unwrap().clear();
    }
}
