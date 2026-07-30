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
use crate::init::network::ipam::IpamConfig;
use crate::init::{
    BANNER, logging, system_runtimes::create_unix_socket_stream,
};
use tonic::async_trait;
use tracing::info;

pub(crate) struct CellSystemRuntime {
    /// The network configuration of the cell. The parent auraed sends it
    /// in the CLI flags. It is `None` for a cell without network isolation
    /// and for a test without networking. Such a cell starts, but it does
    /// not configure `eth0`.
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

        // If the parent sent the `--net-*` flags, configure `eth0` in the
        // network namespace of this process. If the configuration is absent, do
        // nothing. This permits a cell without network isolation and a
        // test without networking.
        if let Some(config) = self.net_config {
            let net = Network::connect(IpamConfig::default())?;
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
