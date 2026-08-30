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
//! # Aurae Daemon
//!
//! Systems daemon built for higher order simple, safe, secure multi-tenant
//! distributed systems.
//!
//! Whether run as pid 1 (init), or a Container, or a Pod it serves standard library
//! functionality over an mTLS backed gRPC server.
//!
//! The Aurae Daemon (auraed) is the main server implementation of the Aurae
//! Standard Library.
//!
//! The Aurae Daemon runs as a gRPC server which listens over a unix domain socket by default.
//!
//! ```bash
//! /var/run/aurae/aurae.sock
//! ```
//!
//! ## Running Auraed
//!
//! Running as `/init` is currently under active development.
//!
//! To run auraed as a standard library server you can run the daemon alongside your current init system.
//!
//! ```bash
//! sudo -E auraed
//! ```
//!
//! See [`The Aurae Standard Library`] for API reference.
//!
//! [`The Aurae Standard Library`]: https://aurae.io/stdlib
// Lint groups: https://doc.rust-lang.org/rustc/lints/groups.html
#![warn(future_incompatible, nonstandard_style, unused)]
#![warn(
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    unconditional_recursion,
    unused_comparisons,
    while_true
)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results
)]
#![warn(clippy::unwrap_used)]

pub use crate::auraed_path::AuraedPath;
use crate::ebpf::{
    BpfContext, SchedProcessForkTracepointProgram,
    SignalSignalGenerateTracepointProgram, TaskstatsExitKProbeProgram,
};
pub use crate::init::network::endpoint::NetworkConfig;
use crate::{
    cells::CellService,
    cri::oci::AuraeOCIBuilder,
    cri::runtime_service::RuntimeService,
    discovery::DiscoveryService,
    init::Context as AuraeContext,
    init::SocketStream,
    init::network::{Network, ipam::IpamConfig},
    logging::log_channel::LogChannel,
    observe::ObserveService,
    spawn::spawn_auraed_oci_to,
};
use anyhow::{Context, anyhow};
use aurae_ebpf_shared::{ForkedProcess, ProcessExit, Signal};
use once_cell::sync::OnceCell;
use proto::{
    cells::cell_service_server::CellServiceServer,
    cri::runtime_service_server::RuntimeServiceServer,
    discovery::discovery_service_server::DiscoveryServiceServer,
    observe::observe_service_server::ObserveServiceServer,
    vms::vm_service_server::VmServiceServer,
};
use std::path::{Path, PathBuf};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::task::JoinHandle;
use tonic::transport::server::Connected;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::{error, info, trace, warn};
use vms::{VmControlToken, VmService};

mod auraed_path;
mod cells;
mod cri;
mod discovery;
mod ebpf;
mod graceful_shutdown;
mod init;
mod logging;
mod observe;
mod spawn;
mod vms;

static AURAED_RUNTIME: OnceCell<AuraedRuntime> = OnceCell::new();

/// Each instance of Aurae holds internal state in memory. Below are the
/// settings which can be configured for a given Aurae daemon instance.
///
/// Note: These fields represent file paths and not the actual authentication
/// material. Each new instance of a subsystem will read these from the local
/// filesystem at runtime in order to authenticate.
#[derive(Debug)]
pub struct AuraedRuntime {
    /// Path to the auraed binary. Defaults to the symbolic link from /proc/self/exe.
    pub auraed: AuraedPath,
    /// Certificate Authority for an organization or mesh of Aurae instances.
    pub ca_crt: PathBuf,
    /// The signed server X509 certificate for this unique instance.
    pub server_crt: PathBuf,
    /// The secret key for this unique instance.
    pub server_key: PathBuf,
    /// Configurable runtime directory. Defaults to /var/run/aurae.
    pub runtime_dir: PathBuf,
    /// Configurable library directory. Defaults to /var/lib/aurae.
    pub library_dir: PathBuf,
    // /// Provides logging channels to expose auraed logging via grpc
    //pub log_collector: Arc<LogChannel>,
}

impl AuraedRuntime {
    pub(crate) fn bundles_dir(&self) -> PathBuf {
        self.runtime_dir.join("bundles")
    }

    pub(crate) fn pods_dir(&self) -> PathBuf {
        self.runtime_dir.join("pods")
    }

    pub(crate) fn default_socket_address(&self) -> PathBuf {
        self.runtime_dir.join("aurae.sock")
    }
}

impl Default for AuraedRuntime {
    fn default() -> Self {
        // In order to prevent their use from other areas, do not make these values into constants.
        AuraedRuntime {
            auraed: AuraedPath::default(),
            ca_crt: PathBuf::from("/etc/aurae/pki/ca.crt"),
            server_crt: PathBuf::from("/etc/aurae/pki/_signed.server.crt"),
            server_key: PathBuf::from("/etc/aurae/pki/server.key"),
            runtime_dir: PathBuf::from("/var/run/aurae"),
            library_dir: PathBuf::from("/var/lib/aurae"),
        }
    }
}

/// Starts the runtime loop for the daemon.
pub async fn run(
    runtime: AuraedRuntime,
    socket: Option<String>,
    verbose: bool,
    nested: bool,
    net_config: Option<NetworkConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with_vm_control(runtime, socket, verbose, nested, net_config, None)
        .await
}

/// Starts the runtime loop with a capability inherited by a nested auraed.
///
/// This is public only for the `auraed` binary; ordinary embedders should use
/// [`run`]. A host daemon passes the capability through an anonymous pipe.
#[doc(hidden)]
pub async fn run_with_vm_control(
    runtime: AuraedRuntime,
    socket: Option<String>,
    verbose: bool,
    nested: bool,
    net_config: Option<NetworkConfig>,
    vm_control_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    async fn inner<T, IO, IE>(
        runtime: &AuraedRuntime,
        context: AuraeContext,
        socket_stream: T,
        net_config: Option<NetworkConfig>,
        vm_control_token: Option<VmControlToken>,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        T: tokio_stream::Stream<Item = Result<IO, IE>> + Send + 'static,
        IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
        IE: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        trace!("{:#?}", runtime);

        let runtime_dir = Path::new(&runtime.runtime_dir);
        // Create runtime directory
        tokio::fs::create_dir_all(runtime_dir).await.with_context(|| {
            format!(
                "Failed to create runtime directory: {}",
                runtime.runtime_dir.display()
            )
        })?;

        // We don't want TLS in cell context
        let mut server = if context != AuraeContext::Cell {
            let server_crt =
                tokio::fs::read(&runtime.server_crt).await.with_context(|| {
                    format!(
                        "Aurae requires a signed TLS certificate to run as a server, but failed to
                        load: '{}'. Please see https://aurae.io/certs/ for information on best
                        practices to quickly generate one.",
                        runtime.server_crt.display()
                    )
                })?;
            let server_key = tokio::fs::read(&runtime.server_key).await?;
            let server_identity = Identity::from_pem(server_crt, server_key);
            info!("Register Server SSL Identity");

            let ca_crt = tokio::fs::read(&runtime.ca_crt).await?;
            let ca_crt_pem = Certificate::from_pem(ca_crt);

            let tls = ServerTlsConfig::new()
                .identity(server_identity)
                .client_ca_root(ca_crt_pem);

            info!(
                "Validating SSL Identity and Root Certificate Authority (CA)"
            );
            //let _log_collector = self.log_collector.clone();

            Server::builder()
                .tls_config(tls)
                .with_context(|| "gRPC server failed to configure tls")?
        } else {
            Server::builder()
        };

        // Install eBPF probes in the host Aurae daemon
        let (_bpf_handle, perf_events) = if context == AuraeContext::Cell
            || context == AuraeContext::Container
        {
            (None, (None, None, None))
        } else {
            // TODO: Add flags/options to "opt-out" of the various BPF probes
            info!("Loading eBPF probes");

            let mut bpf_handle = BpfContext::new();
            let perf_events = (
                bpf_handle.load_and_attach_tracepoint_program::<SchedProcessForkTracepointProgram, ForkedProcess>().ok(),
                bpf_handle.load_and_attach_kprobe_program::<TaskstatsExitKProbeProgram, ProcessExit>().ok(),
                bpf_handle.load_and_attach_tracepoint_program::<SignalSignalGenerateTracepointProgram, Signal>().ok(),
            );

            (Some(bpf_handle), perf_events)
        };

        // Build gRPC Services
        let (health_reporter, health_service) =
            tonic_health::server::health_reporter();

        let observe_service = ObserveService::new(
            LogChannel::new(String::from("auraed")),
            perf_events,
        );
        let observe_service_server =
            ObserveServiceServer::new(observe_service.clone());

        // The daemon owns the `Network` of the host while `inner` runs.
        // The `Network` contains the IPAM allocator. Outside the daemon
        // context there is no cell networking. The value stays
        // `None`. `CellService` then refuses an allocation with
        // `isolate_network` set.
        //
        // `Network` is a cheap clonable handle to shared state.
        // `CellService`, which owns the netkit endpoint of each cell, and
        // `VmService`, which owns the routed TAP of each VM, hold their own
        // clones of it. Both use one pool. The IPAM key prefixes
        // `cell:<name>` and `vm:<id>` keep the two key spaces separate.
        let network: Option<Network> = match context {
            AuraeContext::Daemon => {
                match Network::connect(IpamConfig::default()) {
                    Ok(net) => match net.init_host_network().await {
                        Ok(()) => Some(net),
                        Err(e) => {
                            error!(
                                "Cell networking unavailable: {e}. Cells with \
                                 isolate_network=true cannot be allocated."
                            );
                            None
                        }
                    },
                    Err(e) => {
                        error!(
                            "Failed to connect to netlink for cell \
                             networking: {e}. Cells with \
                             isolate_network=true cannot start without it."
                        );
                        None
                    }
                }
            }
            // A nested auraed in an isolated cell builds its own `Network`
            // from the delegated prefix of that cell. It can then host VMs
            // in the block that the host gave to the cell. Its rtnetlink
            // handle binds to the netns of the cell, where it already runs.
            // Without the `--net-*` flags the cell has no isolated network,
            // the value stays `None`, and the daemon refuses each VM RPC.
            // `build_nested_network` also installs the per-child source
            // filter inside this cell's network namespace.
            AuraeContext::Cell => build_nested_network(net_config.as_ref()),
            _ => None,
        };

        let cell_service =
            CellService::new(observe_service.clone(), network.clone());
        let cell_service_server = CellServiceServer::new(cell_service.clone());
        health_reporter.set_serving::<CellServiceServer<CellService>>().await;

        // VmService shares the cell store with CellService so it can proxy
        // `cell_name`-scoped VM RPCs into a nested auraed.
        let cells_handle = cell_service.cells_handle();

        let discovery_service = DiscoveryService::new();
        let discovery_service_server =
            DiscoveryServiceServer::new(discovery_service);
        health_reporter
            .set_serving::<DiscoveryServiceServer<DiscoveryService>>()
            .await;

        health_reporter
            .set_serving::<ObserveServiceServer<ObserveService>>()
            .await;

        // let pod_service = PodService::new(self.runtime_dir.clone());
        // let pod_service_server = PodServiceServer::new(pod_service.clone());
        // health_reporter.set_serving::<PodServiceServer<PodService>>().await;
        let runtime_service = RuntimeService::new();
        let runtime_service_server =
            RuntimeServiceServer::new(runtime_service.clone());
        health_reporter
            .set_serving::<RuntimeServiceServer<RuntimeService>>()
            .await;

        // VMs are hosted by any auraed that has a `Network`: the host
        // daemon for host VMs, and a nested auraed (seeded above) for VMs
        // inside its cell. `cell_name`-scoped requests are proxied from the
        // host into the target cell's nested auraed, which then hosts the VM
        // locally out of its delegated prefix.
        let vm_service = VmService::new(
            network,
            cells_handle,
            context,
            vm_control_token,
            runtime.library_dir.join("vm"),
        );
        let vm_service_server = VmServiceServer::new(vm_service.clone());
        health_reporter.set_serving::<VmServiceServer<VmService>>().await;

        let graceful_shutdown = graceful_shutdown::GracefulShutdown::new(
            health_reporter,
            cell_service,
            vm_service,
        );
        let graceful_shutdown_signal = graceful_shutdown.subscribe();

        // Run the server concurrently
        // TODO: pass a known-good path to CellService to store any runtime data.
        let server_handle = tokio::spawn(async move {
            server
                .add_service(health_service)
                .add_service(cell_service_server)
                .add_service(discovery_service_server)
                .add_service(observe_service_server)
                // .add_service(pod_service_server)
                .add_service(runtime_service_server)
                .add_service(vm_service_server)
                .serve_with_incoming_shutdown(socket_stream, async {
                    let mut graceful_shutdown_signal = graceful_shutdown_signal;
                    let _ = graceful_shutdown_signal.changed().await;
                    info!("gRPC server received shutdown signal...");
                })
                .await
                .with_context(|| "gRPC server exited with error")?;

            info!("gRPC server exited successfully");

            Ok(())
        });

        // Event loop
        let graceful_shutdown_handle = tokio::spawn(async {
            graceful_shutdown.wait().await;
            Ok(())
        });

        // Flatten function adapted from `try_join` docs.
        async fn flatten<T>(
            handle: JoinHandle<Result<T, anyhow::Error>>,
        ) -> Result<T, anyhow::Error> {
            match handle.await {
                Ok(x) => Ok(x?),
                Err(e) => Err(anyhow!("failed to join task: {e:?}")),
            }
        }

        if let Err(e) = tokio::try_join!(
            flatten(server_handle),
            flatten(graceful_shutdown_handle)
        ) {
            error!("exiting due to error: {e:?}");
        }

        Ok(())
    }

    let runtime = AURAED_RUNTIME.get_or_init(|| runtime);
    let vm_control_token = vm_control_token.map(VmControlToken::from_secret);

    // `init` consumes `net_config` to configure this auraed's own endpoint
    // (eth0) from inside its netns; clone it so `inner` can also seed a
    // nested service `Network`/IPAM from the same delegated prefix.
    let net_config_for_services = net_config.clone();
    let (context, stream) =
        init::init(verbose, nested, socket, net_config).await;
    match stream {
        SocketStream::Tcp(stream) => {
            inner(
                runtime,
                context,
                stream,
                net_config_for_services,
                vm_control_token,
            )
            .await
        }
        SocketStream::Unix(stream) => {
            inner(
                runtime,
                context,
                stream,
                net_config_for_services,
                vm_control_token,
            )
            .await
        }
    }
}

/// Build the seeded service `Network` for a nested auraed running inside an
/// isolated cell, so it can host VMs out of the prefix the host delegated.
/// Returns `None` — VM hosting disabled — when the cell carries no networking
/// (`net_config` absent), has only a single-address (`/128`) delegation with
/// no room to sub-delegate, or netlink/forwarding setup fails. The last is
/// logged so an operator can tell a deliberately unnetworked cell from a
/// setup failure.
///
/// This nested `Network` does not load the cell-net BPF guard (only the host
/// daemon's [`Network::init_host_network`] does). The host eBPF guard pins the
/// outer cell to its delegated block, while an nftables source filter in the
/// cell netns pins each VM TAP or nested-cell interface to its `/128`.
fn build_nested_network(net_config: Option<&NetworkConfig>) -> Option<Network> {
    // No `--net-*` flags means a non-isolated cell with no networking — not
    // an error, so return quietly. A delegated prefix too narrow to
    // sub-delegate is worth a line, so an operator can tell it apart from a
    // netlink/forwarding failure (logged below).
    let net_config = net_config?;
    let Some(ipam_config) = net_config.nested_ipam_config() else {
        warn!(
            "Cell's delegated prefix (/{}) is too narrow to sub-delegate VM \
             addresses; VMs cannot be hosted in this cell.",
            net_config.delegated_prefix_len_v6
        );
        return None;
    };
    match Network::builder()
        .ipam(ipam_config)
        .enable_forwarding()
        .enable_source_filter()
        .build()
    {
        Ok(net) => Some(net),
        Err(e) => {
            error!(
                "Failed to set up nested cell networking: {e}. VMs cannot be \
                 hosted in this cell."
            );
            None
        }
    }
}

/// Write the container OCI spec to the filesystem in preparation for spawning Auraed using a container runtime.
pub fn prep_oci_spec_for_spawn(output: &str) -> Result<(), anyhow::Error> {
    let spec = AuraeOCIBuilder::new()
        .build()
        .map_err(|e| anyhow!("building default oci spec: {e}"))?;
    spawn_auraed_oci_to(PathBuf::from(output), spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auraed_runtime_default_socket_address_should_use_runtime_dir() {
        let default_runtime = AuraedRuntime::default();
        assert_eq!(
            default_runtime.default_socket_address(),
            PathBuf::from("/var/run/aurae/aurae.sock")
        );

        let custom_runtime_dir = PathBuf::from("/tmp/aurae-test-runtime");
        let runtime = AuraedRuntime {
            runtime_dir: custom_runtime_dir.clone(),
            ..Default::default()
        };
        assert_eq!(
            runtime.default_socket_address(),
            custom_runtime_dir.join("aurae.sock")
        );
    }
}
