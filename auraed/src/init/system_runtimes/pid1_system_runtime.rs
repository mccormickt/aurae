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

use super::{SocketStream, SystemRuntime, SystemRuntimeError};
use crate::init::{
    BANNER,
    fs::{CGROUP_MNT_FLAGS, CHMOD_0755, COMMON_MNT_FLAGS, FsError, MountSpec},
    logging,
    network::{self, endpoint::NetworkConfig},
    power::spawn_thread_power_button_listener,
    system_runtimes::create_tcp_socket_stream,
};
use ipnet::Ipv6Net;
use nix::{
    mount::MsFlags,
    unistd::{mkdir, symlinkat},
};
use std::{
    collections::HashMap,
    fs,
    net::{Ipv6Addr, SocketAddr},
    path::Path,
};
use tonic::async_trait;
use tracing::{error, info, trace, warn};

const POWER_BUTTON_DEVICE: &str = "/dev/input/event0";
const DEFAULT_NETWORK_SOCKET_ADDR: &str = "[::]:8080";
const DEFAULT_NET_DEV: &str = "eth0";

/// Parse kernel command line parameters from /proc/cmdline.
///
/// Looks for `aurae.*` parameters:
///  - `aurae.prefix_v6=<addr>/<len>` — delegated IPv6 prefix; first usable
///    address is bound to eth0
///  - `aurae.gw_v6=<addr>` — IPv6 gateway (host-side address)
fn parse_kernel_cmdline() -> HashMap<String, String> {
    let mut params = HashMap::new();
    let cmdline = match fs::read_to_string("/proc/cmdline") {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read /proc/cmdline: {e}");
            return params;
        }
    };
    for param in cmdline.split_whitespace() {
        if let Some(stripped) = param.strip_prefix("aurae.")
            && let Some((key, value)) = stripped.split_once('=')
        {
            let _ = params.insert(key.to_string(), value.to_string());
        }
    }
    params
}

/// Pull a [`NetworkConfig`] out of kernel-cmdline params. The interface
/// name defaults to `eth0` — the conventional VM-NIC name.
fn build_network_config(
    params: &HashMap<String, String>,
) -> Result<NetworkConfig, String> {
    let prefix_v6: Ipv6Net = params
        .get("prefix_v6")
        .ok_or_else(|| "missing aurae.prefix_v6".to_string())?
        .parse()
        .map_err(|e| format!("invalid aurae.prefix_v6: {e}"))?;
    let gateway_v6: Ipv6Addr = params
        .get("gw_v6")
        .ok_or_else(|| "missing aurae.gw_v6".to_string())?
        .parse()
        .map_err(|e| format!("invalid aurae.gw_v6: {e}"))?;

    Ok(NetworkConfig {
        host_v6: gateway_v6,
        // First usable address in the delegated prefix is the guest's NIC
        // address. With a /128 device prefix the network address *is* that
        // address.
        guest_v6: prefix_v6.addr(),
        guest_prefix_len_v6: prefix_v6.prefix_len(),
        interface_name: DEFAULT_NET_DEV.to_owned(),
    })
}

pub(crate) struct Pid1SystemRuntime {
    /// Per-endpoint network config. CLI args take precedence; if `None`,
    /// fall back to parsing `/proc/cmdline` for legacy VM boot paths.
    pub net_config: Option<NetworkConfig>,
}

impl Pid1SystemRuntime {
    fn spawn_system_runtime_threads() {
        // ---- MAIN DAEMON THREAD POOL ----
        // TODO: https://github.com/aurae-runtime/auraed/issues/33
        match spawn_thread_power_button_listener(Path::new(POWER_BUTTON_DEVICE))
        {
            Ok(_) => {
                info!("Spawned power button device listener");
            }
            Err(e) => {
                error!(
                    "Failed to spawn power button device listener. Error={e}"
                );
            }
        }

        // ---- MAIN DAEMON THREAD POOL ----
    }
}

#[async_trait]
impl SystemRuntime for Pid1SystemRuntime {
    // Executing as PID 1 context
    async fn init(
        self,
        verbose: bool,
        socket_address: Option<String>,
    ) -> Result<SocketStream, SystemRuntimeError> {
        println!("{BANNER}");

        // Initialize the PID 1 logger
        logging::init(verbose, false)?;
        info!("Running as pid 1");
        trace!("Configure filesystem");

        mkdir("/dev/pts", *CHMOD_0755).map_err(FsError::FileCreationFailure)?;
        MountSpec {
            source: Some("devpts"),
            target: "/dev/pts",
            fstype: Some("devpts"),
            flags: MsFlags::MS_NOEXEC
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NOATIME,
            data: Some("mode=0620,gid=5,ptmxmode=666"),
        }
        .mount()?;

        MountSpec {
            source: Some("sysfs"),
            target: "/sys",
            fstype: Some("sysfs"),
            flags: *COMMON_MNT_FLAGS,
            data: None,
        }
        .mount()?;

        MountSpec {
            source: Some("proc"),
            target: "/proc",
            fstype: Some("proc"),
            flags: *COMMON_MNT_FLAGS,
            data: None,
        }
        .mount()?;

        MountSpec {
            source: Some("run"),
            target: "/run",
            fstype: Some("tmpfs"),
            flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: Some("mode=0755"),
        }
        .mount()?;

        symlinkat("/proc/self/fd", None, "/dev/fd")
            .map_err(FsError::FileCreationFailure)?;
        symlinkat("/proc/self/fd/0", None, "/dev/stdin")
            .map_err(FsError::FileCreationFailure)?;
        symlinkat("/proc/self/fd/1", None, "/dev/stdout")
            .map_err(FsError::FileCreationFailure)?;
        symlinkat("/proc/self/fd/2", None, "/dev/stderr")
            .map_err(FsError::FileCreationFailure)?;

        MountSpec {
            source: Some("cgroup2"),
            target: "/sys/fs/cgroup",
            fstype: Some("cgroup2"),
            flags: *CGROUP_MNT_FLAGS,
            data: None,
        }
        .mount()?;

        MountSpec {
            source: Some("debugfs"),
            target: "/sys/kernel/debug",
            fstype: Some("debugfs"),
            flags: *COMMON_MNT_FLAGS,
            data: None,
        }
        .mount()?;

        trace!("Configure network");

        // CLI args take precedence; fall back to /proc/cmdline so legacy
        // VM-boot paths (cloud-hypervisor passing aurae.prefix_v6=... and
        // aurae.gw_v6=... on the kernel cmdline) keep working.
        let net_config = match self.net_config {
            Some(cfg) => Some(cfg),
            None => {
                let kernel_params = parse_kernel_cmdline();
                trace!("Kernel params: {kernel_params:?}");
                match build_network_config(&kernel_params) {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        warn!(
                            "No network config on CLI and could not build one \
                             from kernel cmdline: {e}. Skipping guest network \
                             setup."
                        );
                        None
                    }
                }
            }
        };

        let net_config = match net_config {
            Some(cfg) => cfg,
            None => {
                Self::spawn_system_runtime_threads();
                let socket_addr = socket_address
                    .unwrap_or_else(|| DEFAULT_NETWORK_SOCKET_ADDR.into())
                    .parse::<SocketAddr>()?;
                return create_tcp_socket_stream(socket_addr).await;
            }
        };

        info!(
            "IPv6 guest config: v6={}/{} gw={} iface={}",
            net_config.guest_v6,
            net_config.guest_prefix_len_v6,
            net_config.host_v6,
            net_config.interface_name,
        );

        let network = network::Network::connect()?;
        network.init_endpoint(&net_config).await?;

        // TODO: do we need to create an interface and address for socket_address?

        Self::spawn_system_runtime_threads();

        trace!("init of auraed as pid1 done");

        let socket_addr = socket_address
            .unwrap_or_else(|| DEFAULT_NETWORK_SOCKET_ADDR.into())
            .parse::<SocketAddr>()?;
        create_tcp_socket_stream(socket_addr).await
    }
}
