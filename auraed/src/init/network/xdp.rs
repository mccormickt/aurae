//! Owned, routed L3 netkit endpoints for the prepared Cloud Hypervisor API.
//!
//! Each VM has its own pair and queue 0. The shared cell uplink is untouched.
//! Traffic uses the namespace's routing and nftables hooks; neither program
//! redirects to another netdev. All methods run on the VM lifecycle OS thread.

use super::Network;
use super::netlink::{configure_routed_endpoint, netlink_errno, set_link_up};
use crate::ebpf::bpf_file::BpfFile;
use crate::vms::NetSpec;
use anyhow::{Context, Result, ensure};
use aurae_ebpf_shared::xdp::XdpNetConfig;
use aya::{
    Ebpf,
    maps::{HashMap, XskMap},
    programs::{Xdp, XdpFlags, links::FdLink},
};
use futures::TryStreamExt;
use ipnet::Ipv6Net;
use net_util::{PreparedXdpNet, XdpReleaseFence, XdpSocketConfig};
use netlink_packet_route::link::{
    InfoData, InfoNetkit, LinkAttribute, LinkInfo, NetkitMode, NetkitPolicy,
};
use nix::libc;
use rtnetlink::{LinkNetkit, LinkUnspec};
use std::{fmt, os::fd::AsFd, process::Command};

const SOCKET_KEY: u32 = 17;
const BIND_QUEUE: u32 = 0;

struct VmNetProgram;
impl BpfFile for VmNetProgram {
    const OBJ_NAME: &'static str = "guard-xdp-vm-net";
}

struct Steering {
    // Close links before program/map FDs. Nothing is pinned or shared.
    _links: Vec<FdLink>,
    ebpf: Ebpf,
}

/// Non-cloneable runtime lease. Retained after a failed operation for retry.
pub(crate) struct XdpEndpoint {
    primary: String,
    peer: String,
    owner_group: u32,
    created: bool,
    source_bound: bool,
    delegated: Ipv6Net,
    steering: Option<Steering>,
    fence: Option<XdpReleaseFence>,
}

impl fmt::Debug for XdpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdpEndpoint")
            .field("primary", &self.primary)
            .field("peer", &self.peer)
            .field("created", &self.created)
            .field("source_bound", &self.source_bound)
            .finish_non_exhaustive()
    }
}

impl XdpEndpoint {
    pub(crate) fn new(net: &NetSpec) -> Result<Self> {
        let peer = net.xdp_iface.clone().context("missing AF_XDP peer")?;
        let primary =
            peer.strip_suffix("-p").context("invalid AF_XDP peer")?.to_string();
        Ok(Self {
            primary,
            peer,
            owner_group: uuid::Uuid::new_v4().as_fields().0.max(1),
            created: false,
            source_bound: false,
            delegated: Ipv6Net::new(net.guest_ip_v6, net.prefix_len_v6)?,
            steering: None,
            fence: None,
        })
    }

    /// Prepare a fresh resource generation. A failed setup leaves this lease
    /// in the cache; the caller must revoke, stop CH, then clean up or retry.
    pub(crate) async fn prepare(
        &mut self,
        network: &Network,
        net: &NetSpec,
    ) -> Result<PreparedXdpNet> {
        ensure!(self.steering.is_none(), "AF_XDP endpoint is already armed");
        self.wait_released();
        let handle = &network.inner.handle;
        if !self.created {
            // IFLA_GROUP is installed atomically by rtnl_create_link on both
            // endpoints. IFLA_IFALIAS is handled only by link-set requests.
            let mut pair =
                LinkNetkit::new(&self.primary, &self.peer, NetkitMode::L3)
                    .policy(NetkitPolicy::Pass)
                    .peer_policy(NetkitPolicy::Pass)
                    .append_extra_attribute(LinkAttribute::Group(
                        self.owner_group,
                    ))
                    .build();
            for attribute in &mut pair.attributes {
                if let LinkAttribute::LinkInfo(infos) = attribute {
                    for info in infos {
                        if let LinkInfo::Data(InfoData::Netkit(settings)) = info
                        {
                            for setting in settings {
                                if let InfoNetkit::Peer(peer) = setting {
                                    peer.attributes.push(LinkAttribute::Group(
                                        self.owner_group,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            handle
                .link()
                .add(pair)
                .execute()
                .await
                .context("create VM netkit pair")?;
            self.created = true;
        }
        let primary = self
            .owned_link(network, &self.primary)
            .await?
            .context("VM netkit pair disappeared")?;
        let peer = self
            .owned_link(network, &self.peer)
            .await?
            .context("VM netkit peer disappeared")?;

        // Generic XSK copies bytes without skb checksum or GSO metadata.
        // Complete checksums and segmentation before the primary transmits
        // to the peer. Only this VM's owned, down endpoint is changed.
        let offloads = Command::new("ethtool")
            .args([
                "--offload",
                &self.primary,
                "tx",
                "off",
                "sg",
                "off",
                "tso",
                "off",
                "gso",
                "off",
            ])
            .output()
            .context("disable VM endpoint offloads with ethtool")?;
        ensure!(
            offloads.status.success(),
            "disable VM endpoint offloads: {}{}",
            String::from_utf8_lossy(&offloads.stdout),
            String::from_utf8_lossy(&offloads.stderr),
        );

        if !self.source_bound {
            let name = self.primary.clone();
            let delegated = self.delegated;
            network
                .nft(move |nat| nat.bind_cell_source(&name, delegated))
                .await?;
            self.source_bound = true;
        }

        let mut ebpf = VmNetProgram::load().context("load VM AF_XDP policy")?;
        let config = XdpNetConfig {
            delegated: self.delegated.network().octets(),
            prefix_len: u32::from(self.delegated.prefix_len()),
            socket_key: SOCKET_KEY,
            guest_mac: net.mac.get_bytes().try_into().expect("Ethernet MAC"),
            reserved: [0; 2],
        };
        let mut configurations = HashMap::<_, u32, XdpNetConfig>::try_from(
            ebpf.map_mut("VM_CONFIG").context("missing VM_CONFIG")?,
        )?;
        configurations.insert(primary, config, 0)?;
        configurations.insert(peer, config, 0)?;

        let mut links = Vec::new();
        for (name, index) in [("vm_transmit", primary), ("vm_receive", peer)] {
            let program: &mut Xdp = ebpf
                .program_mut(name)
                .context("missing VM XDP program")?
                .try_into()?;
            program.load()?;
            let link = program.attach_to_if_index(index, XdpFlags::SKB_MODE)?;
            // Refuse legacy netlink attachment. FD ownership prevents teardown
            // from removing a replacement program installed by another owner.
            links.push(FdLink::try_from(program.take_link(link)?)?);
        }
        self.steering = Some(Steering { _links: links, ebpf });
        configure_routed_endpoint(
            handle,
            &self.primary,
            net.host_ip_v6,
            self.delegated,
        )
        .await?;
        set_link_up(handle, peer, &self.peer).await?;

        let resource = PreparedXdpNet::new(
            &self.peer,
            BIND_QUEUE,
            XdpSocketConfig::default(),
        )
        .context("bind explicit AF_XDP COPY endpoint")?;
        let steering = self.steering.as_mut().expect("armed steering");
        let mut sockets = XskMap::try_from(
            steering
                .ebpf
                .map_mut("VM_SOCKETS")
                .context("missing VM_SOCKETS")?,
        )?;
        sockets.set(SOCKET_KEY, resource.as_fd(), 0)?;
        self.fence = Some(resource.release_fence());
        Ok(resource)
    }

    /// Stop both directions before dropping links and map socket references.
    /// A failure retains steering, source policy, and the allocation.
    pub(crate) async fn revoke(&mut self, network: &Network) -> Result<()> {
        if self.created
            && let Some(index) = self.owned_link(network, &self.primary).await?
        {
            network
                .inner
                .handle
                .link()
                .set(LinkUnspec::new_with_index(index).down().build())
                .execute()
                .await?;
            let peer = self
                .owned_link(network, &self.peer)
                .await?
                .context("VM netkit peer disappeared")?;
            network
                .inner
                .handle
                .link()
                .set(LinkUnspec::new_with_index(peer).down().build())
                .execute()
                .await?;
        }
        self.steering = None;
        Ok(())
    }

    /// Call only after CH shutdown/join or definite resource rejection.
    pub(crate) fn wait_released(&mut self) {
        if let Some(fence) = self.fence.take() {
            fence.wait();
        }
    }

    /// Remove only this lease's pair, then its source binding. Keep state if
    /// either operation fails. Shared cell links, programs and maps are untouched.
    pub(crate) async fn destroy(&mut self, network: &Network) -> Result<()> {
        ensure!(
            self.steering.is_none() && self.fence.is_none(),
            "AF_XDP resources still live"
        );
        if self.created {
            if let Some(index) = self.owned_link(network, &self.primary).await?
            {
                match network.inner.handle.link().del(index).execute().await {
                    Ok(()) => {}
                    Err(error)
                        if netlink_errno(&error) == Some(-libc::ENODEV) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            self.created = false;
        }
        if self.source_bound {
            let name = self.primary.clone();
            let delegated = self.delegated;
            network
                .nft(move |nat| nat.unbind_cell_source(&name, delegated))
                .await?;
            self.source_bound = false;
        }
        Ok(())
    }

    async fn owned_link(
        &self,
        network: &Network,
        name: &str,
    ) -> Result<Option<u32>> {
        let result = network
            .inner
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await;
        let link = match result {
            Ok(Some(link)) => link,
            Ok(None) => return Ok(None),
            Err(error) if netlink_errno(&error) == Some(-libc::ENODEV) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        ensure!(link.attributes.iter().any(|attribute| matches!(attribute, LinkAttribute::Group(group) if *group == self.owner_group)),
            "refusing to change foreign interface {name}");
        Ok(Some(link.header.index))
    }
}
