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
//! address of each cell and sends cell-to-cell traffic directly into the
//! destination netns with `bpf_redirect_peer()`. The kernel side is in
//! `ebpf/src/guard-tcx-cell-net.rs`.
//!
//! The ifindex of the primary is the key of the map entries. The daemon
//! inserts the entries before it attaches the program, and it attaches the
//! program before the netkit peer moves into the netns of the cell. Thus a
//! cell has no time to send unfiltered traffic. The program drops a packet
//! if the configuration entry is absent. Thus a recycled ifindex fails
//! closed and does not use the policy of a dead cell.
//!
//! [`CellNetGuard::arm_for_cell`] and [`CellNetGuard::publish_redirect`]
//! are separate steps, because their sequence constraints are opposite.
//! The policy must exist before a packet can leave the cell. The redirect
//! entry must not exist before the peer of the cell is up in its own netns.
//!
//! The program uses a tcx attachment on the host-side primary and not a
//! program on the netkit peer, because aya cannot attach to the
//! `bpf_mprog` of netkit (aya#1553). This has two results. First, the pair
//! must use `NetkitPolicy::Pass`, because a `Blackhole` device policy stops
//! the packets before the RX path of the primary, where this program runs.
//! Thus a cell keeps its connectivity if the tcx link ends with the daemon,
//! until the next startup sweep reclaims the interface. The per-cell source
//! binding in [`super::nat`] limits that cell in the interval. Second, the
//! cell-to-cell fast path is `bpf_redirect_peer` from ingress to ingress,
//! which is the veth pattern. It is not the `bpf_redirect` of netkit from
//! egress to egress. Thus the published netkit latency and throughput
//! figures do not apply.
//!
//! The daemon pins nothing. This process is the only owner of the program,
//! of its maps, and of the links of the cells. A link detaches when its
//! [`SchedClassifierLink`] drops. All other state ends with the daemon.

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
use tracing::{error, trace, warn};

use crate::ebpf::bpf_file::BpfFile;

pub(crate) use aya::programs::tc::SchedClassifierLink;

/// The name of the classifier function in
/// `ebpf/src/guard-tcx-cell-net.rs`. Aya uses the function symbol as the
/// name of the program.
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
    redirect: LpmTrie<MapData, [u8; 16], u32>,
    stats: PerCpuHashMap<MapData, u32, CellNetStats>,
}

impl CellNetGuard {
    /// Load the guard ELF from the library directory, load the classifier
    /// into the kernel, and take the maps. `Network::init_host_network`
    /// calls this function one time for each daemon. An error here is fatal
    /// for cell networking. The daemon then refuses each cell and does not
    /// run a cell without the per-cell anti-spoof check.
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

    /// Arm the guard for one cell. The function inserts the zeroed stats
    /// and the source policy of the cell, then attaches the classifier to
    /// `primary`. A kernel 6.6 or later uses tcx. The function returns the
    /// link, and a drop of that link detaches the program.
    ///
    /// The function inserts the map entries before the attach, thus the
    /// program never finds a missing entry. The caller attaches the program
    /// before the netkit peer enters the netns of the cell, thus the cell
    /// cannot send unfiltered traffic.
    ///
    /// The function does not publish the redirect entry of the cell.
    /// [`Self::publish_redirect`] does that. The rollback removes only the
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

    /// Put the delegated prefix of the cell in `CELL_REDIRECT`. The cell
    /// is then a valid target of the `bpf_redirect_peer` fast path of a
    /// sibling cell.
    ///
    /// This function is separate from [`Self::arm_for_cell`], and the
    /// caller calls it only after the endpoint of the cell is up.
    /// `bpf_redirect_peer` finds the netkit peer of the target after the
    /// program returns. It drops the packet if that peer is not `IFF_UP`
    /// or is in the same netns. A publication while the peer is still
    /// admin-down in the host netns would thus discard the traffic of a
    /// sibling cell while the guard counts the packet as `redirected`.
    pub(crate) fn publish_redirect(
        &self,
        ifindex: u32,
        delegated: Ipv6Net,
    ) -> Result<(), CellGuardError> {
        let mut inner =
            self.inner.lock().map_err(|_| CellGuardError::Poisoned)?;
        inner.redirect.insert(&lpm_key(delegated), ifindex, 0)?;
        Ok(())
    }

    /// Deactivate the guard for one cell. The function drops the link,
    /// which detaches the program, and removes the map entries of the cell.
    /// It is best-effort and synchronous, thus the hard-kill path and the
    /// drop path can call it.
    ///
    /// The redirect entry can be absent here, because a teardown can occur
    /// between [`Self::arm_for_cell`] and [`Self::publish_redirect`]. Thus
    /// the function tolerates a missing redirect entry. It does not
    /// tolerate a missing config or stats entry.
    pub(crate) fn disable_for_cell(
        &self,
        ifindex: u32,
        delegated: Ipv6Net,
        link: Option<SchedClassifierLink>,
    ) {
        // A drop of the link closes its fd, and the kernel detaches the
        // program from the device.
        drop(link);

        // Recover from a poisoned lock. The map handles are still valid,
        // and a skipped removal would leak the entries of this cell. An old
        // CELL_REDIRECT entry can send the traffic of a sibling cell to a
        // recycled ifindex.
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| {
            warn!(
                "cell-net guard mutex poisoned; recovering to remove map \
                 entries for ifindex {ifindex}"
            );
            poisoned.into_inner()
        });
        let GuardInner { config, redirect, stats, .. } = &mut *inner;
        // A cell without a publication has no redirect entry.
        if let Err(e) = redirect.remove(&lpm_key(delegated)) {
            trace!(
                "No {MAP_REDIRECT} entry to remove for ifindex {ifindex} \
                 (torn down before publish): {e}"
            );
        }
        remove_map_entry(config.remove(&ifindex), MAP_CONFIG, ifindex);
        remove_map_entry(stats.remove(&ifindex), MAP_STATS, ifindex);
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

/// Remove a map entry of one cell. The caller knows that the entry exists.
/// A leaked entry is a real problem, because an old `CELL_REDIRECT` entry
/// can send the traffic of a sibling cell to a recycled ifindex. Thus a
/// failure here is an alarm and not an expected miss.
fn remove_map_entry(result: Result<(), MapError>, map: &str, ifindex: u32) {
    if let Err(e) = result {
        error!("Failed to remove ifindex {ifindex} from {map}: {e}");
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

        // A delegation that is not a /128 uses the network address as its
        // key.
        let net: Ipv6Net = "fd00:ae::ff00:0:0:1/80".parse().expect("valid net");
        let key = lpm_key(net);
        assert_eq!(key.prefix_len(), 80);
        assert_eq!(key.data(), net.network().octets());
    }
}
