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

use std::path::PathBuf;

use super::{SocketStream, SystemRuntime, SystemRuntimeError};
use crate::AURAED_RUNTIME;
use crate::init::{BANNER, system_runtimes::create_unix_socket_stream};
use crate::logging::log_channel::LogChannel;
use tonic::async_trait;
use tracing::info;

pub(crate) struct CellSystemRuntime {
    log_channel: LogChannel,
}

impl CellSystemRuntime {
    pub(crate) fn new(log_channel: LogChannel) -> Self {
        Self { log_channel }
    }
}

#[async_trait]
impl SystemRuntime for CellSystemRuntime {
    async fn init(
        self,
        verbose: bool,
        socket_address: Option<String>,
    ) -> Result<SocketStream, SystemRuntimeError> {
        println!("{BANNER}");
        // A process-isolated cell runs its nested auraed as PID 1 in a fresh
        // pid namespace with no host syslog to write to, so it logs to stdout
        // only (plus the broadcast layer for log streaming). A non-isolated
        // cell shares the host pid namespace and logs to syslog like the host
        // daemon. This mirrors the historical `std::process::id()` dispatch.
        if std::process::id() == 1 {
            self.log_channel.pid1(verbose)?;
        } else {
            self.log_channel.daemon(verbose)?;
        }
        info!("Running as a cell");
        create_unix_socket_stream(
            socket_address.map(PathBuf::from).unwrap_or_else(|| {
                AURAED_RUNTIME.get().expect("runtime").default_socket_address()
            }),
        )
        .await
    }
}
