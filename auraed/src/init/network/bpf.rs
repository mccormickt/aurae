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

//! The userspace owner of the `guard-tcx-cell-net` eBPF program.
//!
//! The host auraed loads the program one time at the network init. It then
//! attaches the program at tcx ingress on the netkit primary of each cell.
//! All traffic from a cell arrives there. Thus this hook binds the source
//! address of each cell in the datapath, before the packet reaches the
//! host stack. The kernel side is in `ebpf/src/guard-tcx-cell-net.rs`.
//!
//! The program is an optional addition to the nftables ruleset in
//! [`super::nat`], which is the mandatory policy. The program repeats only
//! the per-cell source binding of that ruleset and makes no forwarding
//! decision. It gives each packet with a valid source to the host stack,
//! where nftables decides. Thus the traffic that a cell can send and
//! receive is the same with and without the program. The program adds an
//! early drop of a spoofed source and per-cell counters.
//!
//! The primary ifindex keys the source config and the stats. The daemon
//! inserts the entries before it attaches the program, and it attaches
//! before the netkit peer moves into the cell netns. Thus a cell has no
//! time to send unfiltered traffic. A missing configuration fails closed.
//!
//! The program uses a tcx attachment on the host-side primary and not a
//! program on the netkit peer, because aya cannot attach to the
//! `bpf_mprog` of netkit (aya#1553). Thus the pair must use
//! `NetkitPolicy::Pass`, because a `Blackhole` device policy stops the
//! packets before the RX path of the primary, where this program runs.
//! A cell keeps its connectivity if the tcx link ends with the daemon,
//! until the next startup sweep reclaims the interface. The nft ruleset
//! limits that cell in the interval.
//!
//! Isolated cell networking requires netkit and therefore Linux 6.7 or
//! later. The tcx attachment itself requires Linux 6.6. On a host where the
//! object, verifier, capabilities, or attachment is unavailable, auraed
//! keeps the nft policy and logs the fallback.
//!
//! The source and stats maps each hold 4,096 cells. A cell beyond that
//! limit gets no guard and uses the nft path only. The stats values use
//! `4,096 * 24 * nr_cpus` bytes, before kernel map overhead.
//!
//! The daemon pins nothing. This process is the only owner of the program,
//! of its maps, and of the links of the cells. A link detaches when its
//! [`SchedClassifierLink`] drops. All other state ends with the daemon.

use aurae_ebpf_shared::{CellNetConfig, CellNetStats};
use aya::Ebpf;
use aya::maps::{
    HashMap as BpfHashMap, MapData, MapError, PerCpuHashMap, PerCpuValues,
};
use aya::programs::ProgramError;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use ipnet::Ipv6Net;
use std::sync::Mutex;
use tracing::{error, info, warn};

use crate::ebpf::bpf_file::BpfFile;

pub(crate) use aya::programs::tc::SchedClassifierLink;

/// The name of the classifier function in
/// `ebpf/src/guard-tcx-cell-net.rs`. Aya uses the function symbol as the
/// name of the program.
const PROGRAM_NAME: &str = "cell_ingress";
const MAP_CONFIG: &str = "CELL_CONFIG";
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

/// The marker for [`BpfFile`]. It loads the ELF from
/// `{library_dir}/ebpf/`.
struct CellNetGuardFile;

impl BpfFile for CellNetGuardFile {
    const OBJ_NAME: &'static str = "guard-tcx-cell-net";
}

/// The loaded guard program and the handles of its maps. Each daemon has
/// one instance in its `Network`. The state of a cell is in the maps and in
/// the [`SchedClassifierLink`] from [`Self::arm_for_cell`].
pub(crate) struct CellNetGuard {
    inner: Mutex<GuardInner>,
    nr_cpus: usize,
}

struct GuardInner {
    /// The loaded program. Each map handle below has its own fd, but the
    /// program unloads if this field drops.
    ebpf: Ebpf,
    config: BpfHashMap<MapData, u32, CellNetConfig>,
    stats: PerCpuHashMap<MapData, u32, CellNetStats>,
}

impl CellNetGuard {
    /// Load the guard ELF from the library directory, load the classifier
    /// into the kernel, and take the maps. `Network::init_host_network`
    /// calls this function one time for each daemon. On an error the daemon
    /// runs without the guard; nftables remains the mandatory policy.
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
        let stats = PerCpuHashMap::try_from(
            ebpf.take_map(MAP_STATS)
                .ok_or(CellGuardError::MissingEntity { name: MAP_STATS })?,
        )?;

        let nr_cpus = aya::util::nr_cpus().map_err(|(path, source)| {
            CellGuardError::NrCpus { path, source }
        })?;

        Ok(Self {
            inner: Mutex::new(GuardInner { ebpf, config, stats }),
            nr_cpus,
        })
    }

    /// Arm the guard for one cell. The function inserts the zeroed stats
    /// and the source policy of the cell, then attaches the classifier to
    /// `primary`. A kernel 6.6 or later uses tcx. The function returns the
    /// link, and a drop of that link detaches the program.
    ///
    /// The function inserts the map entries before the attach, thus the
    /// program never finds a missing entry. The caller attaches the program
    /// before the netkit peer enters the netns of the cell, thus the cell
    /// cannot send unfiltered traffic. The rollback removes only the
    /// entries of this call, thus each logged failure is a real failure.
    pub(crate) fn arm_for_cell(
        &self,
        primary: &str,
        ifindex: u32,
        delegated: Ipv6Net,
    ) -> Result<SchedClassifierLink, CellGuardError> {
        let mut inner =
            self.inner.lock().map_err(|_| CellGuardError::Poisoned)?;
        let GuardInner { ebpf, config, stats, .. } = &mut *inner;

        let zeroed =
            PerCpuValues::try_from(vec![CellNetStats::default(); self.nr_cpus])
                .map_err(CellGuardError::PerCpuValues)?;
        stats.insert(ifindex, zeroed, 0)?;

        let cfg = CellNetConfig {
            allowed_net: delegated.network().octets(),
            prefix_len: u32::from(delegated.prefix_len()),
        };
        if let Err(e) = config.insert(ifindex, cfg, 0) {
            remove_map_entry(stats.remove(&ifindex), MAP_STATS, ifindex);
            return Err(e.into());
        }

        match attach_ingress(ebpf, primary) {
            Ok(link) => Ok(link),
            Err(e) => {
                remove_map_entry(config.remove(&ifindex), MAP_CONFIG, ifindex);
                remove_map_entry(stats.remove(&ifindex), MAP_STATS, ifindex);
                Err(e)
            }
        }
    }

    /// Detach the source guard and remove its config and stats entries. The
    /// map removals are idempotent and all are attempted before the first
    /// error is returned, so callers can retain their state and retry.
    pub(crate) fn disarm_source(
        &self,
        ifindex: u32,
        link: Option<SchedClassifierLink>,
    ) -> Result<(), CellGuardError> {
        // A drop of the link closes its fd, and the kernel detaches the
        // program from the device.
        drop(link);

        // Recover from a poisoned lock. The map handles are still valid,
        // and a skipped removal would leak the entries of this cell.
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| {
            warn!(
                "cell-net guard mutex poisoned; recovering to remove map \
                 entries for ifindex {ifindex}"
            );
            poisoned.into_inner()
        });
        let GuardInner { config, stats, .. } = &mut *inner;

        match stats.get(&ifindex, 0) {
            Ok(values) => {
                let total = sum_stats(&values);
                info!(
                    "Cell-net guard final stats for ifindex {ifindex}: \
                     spoof_dropped={}, passed={}, other_dropped={}",
                    total.spoof_dropped, total.passed, total.other_dropped
                );
            }
            Err(MapError::KeyNotFound) => {}
            Err(e) => warn!(
                "Failed to read final {MAP_STATS} values for ifindex \
                 {ifindex}: {e}"
            ),
        }

        // Try both removals even if the first fails. A successful removal
        // is treated as complete on a later retry.
        let config_result = remove_if_present(config.remove(&ifindex));
        let stats_result = remove_if_present(stats.remove(&ifindex));
        if let Err(e) = config_result {
            return Err(e.into());
        }
        if let Err(e) = stats_result {
            return Err(e.into());
        }
        Ok(())
    }
}

fn sum_stats(values: &PerCpuValues<CellNetStats>) -> CellNetStats {
    let mut total = CellNetStats::default();
    for value in values.iter() {
        total.spoof_dropped =
            total.spoof_dropped.saturating_add(value.spoof_dropped);
        total.passed = total.passed.saturating_add(value.passed);
        total.other_dropped =
            total.other_dropped.saturating_add(value.other_dropped);
    }
    total
}

/// Delete a map key as an idempotent cleanup operation.
fn remove_if_present(result: Result<(), MapError>) -> Result<(), MapError> {
    match result {
        Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Attach the guard classifier at tcx ingress on `iface` and return the
/// link.
fn attach_ingress(
    ebpf: &mut Ebpf,
    iface: &str,
) -> Result<SchedClassifierLink, CellGuardError> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(PROGRAM_NAME)
        .ok_or(CellGuardError::MissingEntity { name: PROGRAM_NAME })?
        .try_into()?;
    let link_id = prog.attach(iface, TcAttachType::Ingress)?;
    Ok(prog.take_link(link_id)?)
}

/// Remove a map entry during rollback. The caller knows that it exists, so
/// a failure is an alarm and can consume finite map capacity.
fn remove_map_entry(result: Result<(), MapError>, map: &str, key: u32) {
    if let Err(e) = result {
        error!("Failed to remove key {key} from {map}: {e}");
    }
}
