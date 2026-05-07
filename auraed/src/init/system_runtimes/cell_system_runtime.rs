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
use crate::init::network::Network;
use crate::init::network::endpoint::NetworkConfig;
use crate::init::{
    BANNER, logging, system_runtimes::create_unix_socket_stream,
};
use tonic::async_trait;
use tracing::info;

pub(crate) struct CellSystemRuntime {
    /// Per-cell network config passed by the parent auraed via CLI
    /// flags. `None` for non-isolated cells and tests that don't request
    /// networking — in which case the cell still starts but no `eth0`
    /// configuration is performed.
    pub net_config: Option<NetworkConfig>,
}

#[async_trait]
impl SystemRuntime for CellSystemRuntime {
    async fn init(
        self,
        verbose: bool,
        socket_address: Option<String>,
    ) -> Result<SocketStream, SystemRuntimeError> {
        println!("{BANNER}");
        logging::init(verbose, false)?;
        info!("Running as a cell");

        // If the parent passed --net-* flags, configure eth0 from inside
        // our (already-cloned-into) netns. Skipping silently when the
        // config is absent allows non-isolated cells and tests that
        // don't request networking.
        if let Some(config) = self.net_config {
            let net = Network::connect()?;
            net.init_endpoint(&config).await?;
        }

        create_unix_socket_stream(
            socket_address.map(PathBuf::from).unwrap_or_else(|| {
                AURAED_RUNTIME.get().expect("runtime").default_socket_address()
            }),
        )
        .await
    }
}
