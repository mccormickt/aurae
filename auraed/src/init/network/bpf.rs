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
//! The primary ifindex keys the source config and stats. Redirects use two
//! maps: a prefix resolves to a non-reused publication ID, and that ID
//! resolves through a `DEVMAP_HASH` to a specific net_device. The kernel
//! removes the latter entry when the device is unregistered, so a stale
//! prefix cannot target a replacement that reuses the ifindex.
//!
//! The daemon inserts source entries before it attaches the program, and it
//! attaches before the netkit peer moves into the cell netns. Thus a cell
//! has no time to send unfiltered traffic. A missing configuration fails
//! closed.
//!
//! [`CellNetGuard::arm_for_cell`] and [`CellNetGuard::publish_redirect`]
//! are separate steps, because their sequence constraints are opposite.
//! The policy must exist before a packet can leave the cell. The redirect
//! entry must not exist before the peer of the cell is up in its own netns.
//! The matching [`CellNetGuard::unpublish_redirect`] runs before the target
//! netns or interface can disappear.
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
//! figures do not apply, and this fast path makes no performance guarantee
//! without a workload-specific benchmark.
//!
//! Isolated cell networking requires netkit and therefore Linux 6.7 or
//! later. The tcx attachment itself requires Linux 6.6. On a host where the
//! object, verifier, helper, capabilities, or attachment is unavailable,
//! auraed keeps the mandatory nft policy and uses the host-stack path.
//!
//! The source, stats, and live-target maps each hold 4,096 cells. That is
//! the effective fast-path capacity; cells beyond it fall back to nft. The
//! stats values alone use `4,096 * 40 * nr_cpus` bytes, before kernel map
//! overhead. Redirect prefixes have a separate 8,192-entry limit.
//!
//! The daemon pins nothing. This process is the only owner of the program,
//! of its maps, and of the links of the cells. A link detaches when its
//! [`SchedClassifierLink`] drops. All other state ends with the daemon.

use aurae_ebpf_shared::{CellNetConfig, CellNetStats};
use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::xdp::{DevMapHash, XdpMapError};
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
const MAP_REDIRECT: &str = "CELL_REDIRECT";
const MAP_TARGETS: &str = "CELL_TARGETS";
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
    #[error(transparent)]
    XdpMap(#[from] XdpMapError),
    #[error("cell-net redirect publication IDs exhausted")]
    RedirectIdsExhausted,
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
    targets: DevMapHash<MapData>,
    stats: PerCpuHashMap<MapData, u32, CellNetStats>,
    /// IDs are never reused while these unpinned maps exist. This prevents a
    /// stale prefix from naming a replacement device after ifindex reuse.
    next_redirect_id: Option<u32>,
}

impl CellNetGuard {
    /// Load the guard ELF from the library directory, load the classifier
    /// into the kernel, and take the maps. `Network::init_host_network`
    /// calls this function one time for each daemon. An error disables the
    /// redirect fast path; nftables remains the mandatory enforcement layer.
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
        let targets = DevMapHash::try_from(
            ebpf.take_map(MAP_TARGETS)
                .ok_or(CellGuardError::MissingEntity { name: MAP_TARGETS })?,
        )?;
        let stats = PerCpuHashMap::try_from(
            ebpf.take_map(MAP_STATS)
                .ok_or(CellGuardError::MissingEntity { name: MAP_STATS })?,
        )?;

        let nr_cpus = aya::util::nr_cpus().map_err(|(path, source)| {
            CellGuardError::NrCpus { path, source }
        })?;

        Ok(Self {
            inner: Mutex::new(GuardInner {
                ebpf,
                config,
                redirect,
                targets,
                stats,
                next_redirect_id: Some(1),
            }),
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
    /// sibling cell while the guard counts a redirect attempt.
    pub(crate) fn publish_redirect(
        &self,
        ifindex: u32,
        delegated: Ipv6Net,
    ) -> Result<u32, CellGuardError> {
        let mut inner =
            self.inner.lock().map_err(|_| CellGuardError::Poisoned)?;
        let redirect_id = take_redirect_id(&mut inner.next_redirect_id)?;

        // Publish the identity-bearing target first. The kernel removes this
        // entry by net_device identity on NETDEV_UNREGISTER. The prefix map
        // contains only the non-reused ID, never a recyclable ifindex.
        inner.targets.insert(redirect_id, ifindex, None, 0)?;
        if let Err(error) =
            inner.redirect.insert(&lpm_key(delegated), redirect_id, 0)
        {
            remove_map_entry(
                inner.targets.remove(redirect_id),
                MAP_TARGETS,
                redirect_id,
            );
            return Err(error.into());
        }
        Ok(redirect_id)
    }

    /// Remove a cell as a redirect target. The operation is idempotent so a
    /// teardown retry can safely repeat it. The caller must complete this
    /// operation before allowing the target netns or primary to disappear.
    pub(crate) fn unpublish_redirect(
        &self,
        delegated: Ipv6Net,
        redirect_id: u32,
    ) -> Result<(), CellGuardError> {
        let mut inner =
            self.inner.lock().map_err(|_| CellGuardError::Poisoned)?;
        // Removing the identity-bearing target first makes concurrent
        // packets fall back to the host stack before the prefix disappears.
        // Try both removals so a retry only has to finish the failed step.
        let target_result =
            remove_if_present(inner.targets.remove(redirect_id));
        let redirect_result =
            remove_if_present(inner.redirect.remove(&lpm_key(delegated)));
        if let Err(error) = target_result {
            return Err(error.into());
        }
        if let Err(error) = redirect_result {
            return Err(error.into());
        }
        Ok(())
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
                     spoof_dropped={}, redirect_attempted={}, \
                     redirect_missed={}, passed={}, other_dropped={}",
                    total.spoof_dropped,
                    total.redirect_attempted,
                    total.redirect_missed,
                    total.passed,
                    total.other_dropped
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
        total.redirect_attempted =
            total.redirect_attempted.saturating_add(value.redirect_attempted);
        total.redirect_missed =
            total.redirect_missed.saturating_add(value.redirect_missed);
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

fn take_redirect_id(next: &mut Option<u32>) -> Result<u32, CellGuardError> {
    let id = next.ok_or(CellGuardError::RedirectIdsExhausted)?;
    *next = id.checked_add(1);
    Ok(id)
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

    #[test]
    fn redirect_ids_are_not_reused_after_wrap() {
        let mut next = Some(u32::MAX);
        assert_eq!(take_redirect_id(&mut next).unwrap(), u32::MAX);
        assert!(matches!(
            take_redirect_id(&mut next),
            Err(CellGuardError::RedirectIdsExhausted)
        ));
    }
}
