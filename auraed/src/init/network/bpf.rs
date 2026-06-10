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

//! Userspace owner of the `guard-tcx-cell-net` eBPF program.
//!
//! The host auraed loads the program once at network init and attaches it
//! at tc(x) ingress on every cell's netkit primary. All cell-emitted
//! traffic surfaces there, so that single hook enforces per-cell
//! source-address binding and delivers cell→cell traffic directly into
//! the destination netns via `bpf_redirect_peer()` (see
//! `ebpf/src/guard-tcx-cell-net.rs` for the kernel side).
//!
//! Map entries are keyed by the primary's ifindex and are inserted
//! *before* the program is attached, and the program is attached *before*
//! the netkit peer moves into the cell's netns — so there is no window
//! where a cell can emit unfiltered traffic. The program drops on a
//! missing config entry, which makes a recycled ifindex fail closed
//! rather than inherit a dead cell's policy.
//!
//! Nothing is pinned: this daemon process is the single owner of the
//! program, its maps, and the per-cell links. Links detach when their
//! [`SchedClassifierLink`] drops; everything else dies with the daemon.

use aurae_ebpf_shared::{CellNetConfig, CellNetStats};
use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{
    HashMap as BpfHashMap, MapData, MapError, PerCpuHashMap, PerCpuValues,
};
use aya::programs::ProgramError;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use ipnet::Ipv6Net;
use std::sync::Mutex;
use tracing::warn;

use crate::ebpf::bpf_file::BpfFile;

pub(crate) use aya::programs::tc::SchedClassifierLink;

/// Function name of the classifier in `ebpf/src/guard-tcx-cell-net.rs`;
/// aya names the program after the function symbol.
const PROGRAM_NAME: &str = "cell_ingress";
const MAP_CONFIG: &str = "CELL_CONFIG";
const MAP_REDIRECT: &str = "CELL_REDIRECT";
const MAP_STATS: &str = "CELL_STATS";

#[derive(thiserror::Error, Debug)]
pub enum CellGuardError {
    #[error("failed to load eBPF object: {0}")]
    Load(#[from] aya::EbpfError),
    #[error("eBPF object is missing expected program or map `{name}`")]
    MissingEntity { name: &'static str },
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error(transparent)]
    Map(#[from] MapError),
    #[error("failed to determine CPU count from {path}: {source}")]
    NrCpus { path: &'static str, source: std::io::Error },
    #[error("failed to build per-CPU stats values: {0}")]
    PerCpuValues(std::io::Error),
    #[error("cell-net guard mutex poisoned")]
    Poisoned,
}

/// Marker for [`BpfFile`]: loads the ELF from `{library_dir}/ebpf/`.
struct CellNetGuardFile;

impl BpfFile for CellNetGuardFile {
    const OBJ_NAME: &'static str = "guard-tcx-cell-net";
}

/// The loaded guard program plus owned handles to its maps. One instance
/// per daemon, shared behind `Network`; per-cell state lives in the maps
/// and in the [`SchedClassifierLink`] returned by
/// [`Self::enable_for_cell`].
pub(crate) struct CellNetGuard {
    inner: Mutex<GuardInner>,
    nr_cpus: usize,
}

struct GuardInner {
    /// Owns the loaded program. Map handles below hold their own fds, but
    /// the program itself unloads if this drops.
    ebpf: Ebpf,
    config: BpfHashMap<MapData, u32, CellNetConfig>,
    redirect: LpmTrie<MapData, [u8; 16], u32>,
    stats: PerCpuHashMap<MapData, u32, CellNetStats>,
}

impl CellNetGuard {
    /// Load the guard ELF from the library dir, load the classifier into
    /// the kernel, and take ownership of its maps. Called once per daemon
    /// from `Network::init_host_network`; any error there degrades the
    /// daemon to no-guard operation (logged, not fatal).
    pub(crate) fn load() -> Result<Self, CellGuardError> {
        let mut ebpf = CellNetGuardFile::load()?;

        let prog: &mut SchedClassifier = ebpf
            .program_mut(PROGRAM_NAME)
            .ok_or(CellGuardError::MissingEntity { name: PROGRAM_NAME })?
            .try_into()?;
        prog.load()?;

        let config = BpfHashMap::try_from(
            ebpf.take_map(MAP_CONFIG)
                .ok_or(CellGuardError::MissingEntity { name: MAP_CONFIG })?,
        )?;
        let redirect = LpmTrie::try_from(
            ebpf.take_map(MAP_REDIRECT)
                .ok_or(CellGuardError::MissingEntity { name: MAP_REDIRECT })?,
        )?;
        let stats = PerCpuHashMap::try_from(
            ebpf.take_map(MAP_STATS)
                .ok_or(CellGuardError::MissingEntity { name: MAP_STATS })?,
        )?;

        let nr_cpus = aya::util::nr_cpus().map_err(|(path, source)| {
            CellGuardError::NrCpus { path, source }
        })?;

        Ok(Self {
            inner: Mutex::new(GuardInner { ebpf, config, redirect, stats }),
            nr_cpus,
        })
    }

    /// Activate the guard for one cell: insert zeroed stats, the cell's
    /// source policy, and its redirect entry, then attach the classifier
    /// to `primary` (tcx ingress on kernels ≥ 6.6). Returns the owned
    /// link — dropping it detaches the program.
    ///
    /// Map inserts happen before the attach so the program never runs
    /// against missing entries; any failure rolls back whatever was
    /// already inserted.
    pub(crate) fn enable_for_cell(
        &self,
        primary: &str,
        ifindex: u32,
        delegated: Ipv6Net,
    ) -> Result<SchedClassifierLink, CellGuardError> {
        let mut inner =
            self.inner.lock().map_err(|_| CellGuardError::Poisoned)?;
        let GuardInner { ebpf, config, redirect, stats } = &mut *inner;

        let zeroed =
            PerCpuValues::try_from(vec![CellNetStats::default(); self.nr_cpus])
                .map_err(CellGuardError::PerCpuValues)?;
        stats.insert(ifindex, zeroed, 0)?;

        let result = (|| {
            config.insert(
                ifindex,
                CellNetConfig {
                    allowed_net: delegated.network().octets(),
                    prefix_len: u32::from(delegated.prefix_len()),
                },
                0,
            )?;

            let result = (|| {
                redirect.insert(&lpm_key(delegated), ifindex, 0)?;

                let prog: &mut SchedClassifier = ebpf
                    .program_mut(PROGRAM_NAME)
                    .ok_or(CellGuardError::MissingEntity {
                        name: PROGRAM_NAME,
                    })?
                    .try_into()?;
                let link_id = prog
                    .attach(primary, TcAttachType::Ingress)
                    .and_then(|link_id| prog.take_link(link_id));
                match link_id {
                    Ok(link) => Ok(link),
                    Err(e) => {
                        remove_quiet(
                            redirect.remove(&lpm_key(delegated)),
                            MAP_REDIRECT,
                            ifindex,
                        );
                        Err(e.into())
                    }
                }
            })();
            if result.is_err() {
                remove_quiet(config.remove(&ifindex), MAP_CONFIG, ifindex);
            }
            result
        })();
        if result.is_err() {
            remove_quiet(stats.remove(&ifindex), MAP_STATS, ifindex);
        }
        result
    }

    /// Deactivate the guard for one cell: detach the link (by dropping
    /// it) and remove the cell's map entries. Best-effort and fully
    /// synchronous so hard-kill and drop paths can call it; a leaked
    /// entry only wastes map space — the recycled-ifindex case fails
    /// closed in the program either way.
    pub(crate) fn disable_for_cell(
        &self,
        ifindex: u32,
        delegated: Ipv6Net,
        link: Option<SchedClassifierLink>,
    ) {
        // Dropping the link closes its fd and the kernel detaches the
        // program from the device (when the device still exists at all).
        drop(link);

        let Ok(mut inner) = self.inner.lock() else {
            warn!(
                "cell-net guard mutex poisoned — map entries for ifindex \
                 {ifindex} leak until daemon restart"
            );
            return;
        };
        let GuardInner { config, redirect, stats, .. } = &mut *inner;
        remove_quiet(
            redirect.remove(&lpm_key(delegated)),
            MAP_REDIRECT,
            ifindex,
        );
        remove_quiet(config.remove(&ifindex), MAP_CONFIG, ifindex);
        remove_quiet(stats.remove(&ifindex), MAP_STATS, ifindex);
    }
}

/// Log-and-continue for cleanup-path map removals: the only expected
/// failure is "already gone", and cleanup must keep going regardless.
fn remove_quiet(result: Result<(), MapError>, map: &str, ifindex: u32) {
    if let Err(e) = result {
        warn!("Failed to remove ifindex {ifindex} from {map}: {e}");
    }
}

fn lpm_key(net: Ipv6Net) -> Key<[u8; 16]> {
    Key::new(u32::from(net.prefix_len()), net.network().octets())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpm_key_uses_network_address_and_prefix_len() {
        let net: Ipv6Net = "fd00:ae::2/128".parse().expect("valid net");
        let key = lpm_key(net);
        assert_eq!(key.prefix_len(), 128);
        assert_eq!(key.data(), net.addr().octets());

        // A non-/128 delegation keys on the canonical network address.
        let net: Ipv6Net = "fd00:ae::ff00:0:0:1/80".parse().expect("valid net");
        let key = lpm_key(net);
        assert_eq!(key.prefix_len(), 80);
        assert_eq!(key.data(), net.network().octets());
    }
}
