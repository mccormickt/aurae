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

//! Aurae daemon entrypoint wiring CLI parsing to the runtime launcher.

// Lint groups: https://doc.rust-lang.org/rustc/lints/groups.html
#![warn(
    future_incompatible,
    nonstandard_style,
    unused,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    unconditional_recursion,
    unused_comparisons,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results
)]
// Keep the entrypoint warnings clean even when clippy isn't run separately.
#![warn(clippy::all, clippy::pedantic, clippy::unwrap_used)]

use auraed::{AuraedRuntime, NetworkConfig, prep_oci_spec_for_spawn, run};
use clap::{Parser, Subcommand};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use tracing::{error, info};

const DEFAULT_INTERFACE_NAME: &str = "eth0";
const DEFAULT_GUEST_PREFIX_V6: u8 = 128;

/// Command line options for auraed.
///
/// Defines the configurable options which can be used to populate
/// an `AuraeRuntime` structure.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct AuraedOptions {
    /// The signed server certificate. Defaults to /etc/aurae/pki/_signed.server.crt
    #[clap(long, value_parser)]
    server_crt: Option<String>,
    /// The secret server key. Defaults to /etc/aurae/pki/server.key
    #[clap(long, value_parser)]
    server_key: Option<String>,
    /// The CA certificate. Defaults to /etc/aurae/pki/ca.crt
    #[clap(long, value_parser)]
    ca_crt: Option<String>,
    /// Aurae socket address.  Depending on context, this should be a file or a network address.
    /// Defaults to ${`runtime_dir`}/aurae.sock or [`::1`]:8080 respectively.
    ///
    /// Warning: This socket is created (by default) with user
    /// mode 0o766 which allows for unprivileged access to the
    /// auraed daemon which can in turn be used to execute privileged
    /// processes and commands. Access to the socket must be governed
    /// by an appropriate mTLS Authorization setting in order to maintain
    /// a secure multi tenant system.
    #[clap(short, long, value_parser)]
    socket: Option<String>,
    /// Aurae runtime path.  Defaults to /var/run/aurae.
    ///
    /// Here is where the auraed daemon will store artifacts such as
    /// OCI bundles for containers, the aurae.sock socket file, and
    /// runtime pod configuration.
    ///
    /// This is the main "runtime" location for all artifacts that are
    /// a consequence of runtime operations.
    ///
    /// All aspects of the auraed daemon should respect this value.
    #[clap(short, long, value_parser)]
    runtime_dir: Option<String>,
    /// Aurae library path. Defaults to /var/lib/aurae
    ///
    /// Here is where the daemon will look for artifacts such as eBPF
    /// bytecode (ELF objects/probes) and other dependencies that can
    /// optionally be included at runtime.
    ///
    /// All aspects of the auraed library and dependency artifacts
    /// should respect this value.
    #[clap(short, long, value_parser)]
    library_dir: Option<String>,
    /// Toggle verbosity. Default false
    #[clap(short, long, alias = "ritz")]
    verbose: bool,
    /// Run auraed as a nested instance of itself in an Aurae cell.
    #[clap(long)]
    nested: bool,
    /// The IPv6 gateway address of the auraed endpoint. The parent auraed
    /// sets it for a nested auraed in an isolated cell network namespace. The VM boot
    /// path also sets it. The daemon binds the related
    /// `--net-guest-ip-v6` on `eth0` and adds a default route through this
    /// address. The flag is necessary if another `--net-*` flag is set.
    #[clap(long, value_parser)]
    net_host_ip_v6: Option<Ipv6Addr>,
    /// The IPv6 address on `eth0` in the network namespace of the daemon. The flag is
    /// necessary if another `--net-*` flag is set.
    #[clap(long, value_parser)]
    net_guest_ip_v6: Option<Ipv6Addr>,
    /// The prefix length of `--net-guest-ip-v6`. The default is 128 and
    /// gives one address. Use a shorter prefix, for example 80, to give a
    /// delegated prefix to a nested auraed or to a VM.
    #[clap(long, value_parser)]
    net_guest_prefix_v6: Option<u8>,
    /// The interface name that the daemon waits for at its start. The
    /// daemon then renames the interface to `eth0`. The parent gives a
    /// cell a unique peer name, for example `nk-a1b2c3d4-p`. A VM usually
    /// has `eth0` already. The default is `eth0`, and the daemon then does
    /// no rename.
    #[clap(long, value_parser)]
    net_interface_name: Option<String>,
    // Subcommands for the project
    #[clap(subcommand)]
    subcmd: Option<SubCommands>,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    Spawn {
        #[clap(short, long, value_parser, default_value = ".")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match dispatch().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("{err:?}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = AuraedOptions::parse();

    match options.subcmd.take() {
        Some(SubCommands::Spawn { output }) => handle_spawn_subcommand(&output),
        None => handle_default(options).await,
    }
}

async fn handle_default(
    options: AuraedOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Aurae Daemon Runtime");
    info!("Aurae Daemon is pid {}", std::process::id());

    // Destructure the options into individual variables
    let AuraedOptions {
        server_crt,
        server_key,
        ca_crt,
        socket,
        runtime_dir,
        library_dir,
        verbose,
        nested,
        net_host_ip_v6,
        net_guest_ip_v6,
        net_guest_prefix_v6,
        net_interface_name,
        subcmd: _,
    } = options;

    // A networked endpoint needs both `host_v6` and `guest_v6`. The
    // `prefix_v6` and `interface_name` values are optional and have
    // defaults. The function ignores them if the two addresses are
    // absent.
    let net_config = match (net_host_ip_v6, net_guest_ip_v6) {
        (Some(host_v6), Some(guest_v6)) => Some(NetworkConfig {
            host_v6,
            guest_v6,
            guest_prefix_len_v6: net_guest_prefix_v6
                .unwrap_or(DEFAULT_GUEST_PREFIX_V6),
            interface_name: net_interface_name
                .unwrap_or_else(|| DEFAULT_INTERFACE_NAME.to_string()),
        }),
        (None, None) => None,
        _ => {
            return Err("partial network config: --net-host-ip-v6 and \
                        --net-guest-ip-v6 must be set together"
                .into());
        }
    };

    // Destructure the default runtime into individual variables
    let AuraedRuntime {
        auraed: default_auraed,
        ca_crt: default_ca_crt,
        server_crt: default_server_crt,
        server_key: default_server_key,
        runtime_dir: default_runtime_dir,
        library_dir: default_library_dir,
    } = AuraedRuntime::default();

    // Create a new runtime configuration, using provided options or defaults
    let runtime = AuraedRuntime {
        auraed: default_auraed,
        ca_crt: ca_crt.map_or(default_ca_crt, PathBuf::from),
        server_crt: server_crt.map_or(default_server_crt, PathBuf::from),
        server_key: server_key.map_or(default_server_key, PathBuf::from),
        runtime_dir: runtime_dir.map_or(default_runtime_dir, PathBuf::from),
        library_dir: library_dir.map_or(default_library_dir, PathBuf::from),
    };

    // Run the auraed daemon with the configured runtime
    run(runtime, socket, verbose, nested, net_config).await?;
    Ok(())
}

fn handle_spawn_subcommand(
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Spawning Auraed OCI bundle: {}", output);
    prep_oci_spec_for_spawn(output)?; // Prepare the OCI spec for spawning
    Ok(())
}
