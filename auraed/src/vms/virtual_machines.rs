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
use std::collections::HashMap;
use std::net::Ipv6Addr;

use anyhow::anyhow;
use ipnet::Ipv6Net;
use net_util::MacAddr;
use tracing::{error, warn};
use vmm_sys_util::signal::block_signal;

use crate::init::network::Network;
use crate::init::network::ipam::{Allocation, IpamError, vm_key};
#[cfg(feature = "af-xdp")]
use crate::init::network::xdp::XdpEndpoint;

use super::virtual_machine::{NetSpec, VirtualMachine, VmID, VmSpec};

type Cache = HashMap<VmID, VirtualMachine>;

/// The host-side endpoint of the routed TAP of a VM, from its [`NetSpec`].
struct TapEndpoint {
    tap: String,
    host_ip: Ipv6Addr,
    delegated: Ipv6Net,
}

/// Build the two `aurae.*=` kernel cmdline args a guest's pid1 needs to
/// self-configure its NIC: the delegated IPv6 prefix and the host-side
/// IPv6 gateway. pid1's parser is order-independent, but keep the order
/// stable (prefix, gateway) for predictable test assertions.
fn aurae_kernel_args(allocation: &Allocation) -> [String; 2] {
    [
        format!("aurae.prefix_v6={}", allocation.delegated),
        format!("aurae.gw_v6={}", allocation.host_ip),
    ]
}

fn tap_endpoint(
    vm: &VirtualMachine,
) -> Result<Option<TapEndpoint>, anyhow::Error> {
    let Some(net) = vm.vm.net.first() else { return Ok(None) };
    let Some(tap) = net.tap.clone() else { return Ok(None) };
    let delegated = Ipv6Net::new(net.guest_ip_v6, net.prefix_len_v6)
        .map_err(|e| anyhow!("Invalid delegated prefix on NetSpec: {e}"))?;
    Ok(Some(TapEndpoint { tap, host_ip: net.host_ip_v6, delegated }))
}

/// The in-memory cache of virtual machines ([VirtualMachine]) created with Aurae.
#[derive(Debug)]
pub struct VirtualMachines {
    cache: Cache,
    #[cfg(feature = "af-xdp")]
    xdp: HashMap<VmID, XdpEndpoint>,
    /// Shared host networking (which owns the IPAM allocator). `None`
    /// outside the Daemon context and on hosts where networking setup
    /// failed; `create()` returns an error in that case.
    network: Option<Network>,
}

impl Default for VirtualMachines {
    fn default() -> Self {
        Self::new(None)
    }
}

impl VirtualMachines {
    /// Create a new instance of the virtual machines cache.
    pub fn new(network: Option<Network>) -> Self {
        // Mask the signals handled by the Cloud Hypervisor VMM so they only
        // run on the dedicated signal handling thread.
        for sig in &vmm::vm::Vm::HANDLED_SIGNALS {
            if let Err(e) = block_signal(*sig) {
                error!("Error blocking signals: {e}");
            }
        }

        for sig in &vmm::Vmm::HANDLED_SIGNALS {
            if let Err(e) = block_signal(*sig) {
                error!("Error blocking signals: {e}");
            }
        }

        Self {
            cache: Cache::new(),
            network,
            #[cfg(feature = "af-xdp")]
            xdp: HashMap::new(),
        }
    }

    /// Create a new virtual machine
    pub fn create(
        &mut self,
        id: VmID,
        mut spec: VmSpec,
    ) -> Result<VirtualMachine, anyhow::Error> {
        if let Some(vm) = self.cache.get(&id) {
            return Err(anyhow!(
                "Virtual machine with ID '{:?}' already exists: {:?}",
                &id,
                vm.vm,
            ));
        }

        // Populate the default network configuration if it's empty.
        if spec.net.is_empty() {
            let network = self.network.as_ref().ok_or_else(|| {
                anyhow!(
                    "VM networking is unavailable on this daemon — refusing \
                     to allocate"
                )
            })?;

            let allocation = network
                .ipam()
                .allocate(&vm_key(&id))
                .map_err(|e| anyhow!("Failed to allocate IP address: {e}"))?;

            let af_xdp = spec.network.backend
                == proto::vms::VmNetworkBackend::AfXdp as i32;
            let (tap, xdp_iface) = if af_xdp {
                let (_, peer) = network.reserve_interface_names();
                (None, Some(peer))
            } else {
                (Some(network.reserve_tap_name()), None)
            };

            spec.net.push(NetSpec {
                id: spec.network.id.clone(),
                tap,
                xdp_iface,
                mac: MacAddr::local_random(),
                host_mac: None,
                host_ip_v6: allocation.host_ip,
                guest_ip_v6: allocation.guest_ip,
                prefix_len_v6: allocation.delegated.prefix_len(),
            });

            spec.kernel_args.extend(aurae_kernel_args(&allocation));
            if af_xdp {
                // The L3 netkit gateway has no Ethernet address. A permanent
                // neighbor avoids ND and emits the device's zero destination.
                spec.kernel_args.push("aurae.gw_mac=00:00:00:00:00:00".into());
            }
        }

        let vm = match VirtualMachine::new(id.clone(), spec) {
            Ok(vm) => vm,
            Err(e) => {
                // Roll back the IPAM reservation on VMM construction
                // failure. Ignore NotAllocated, which means the caller
                // supplied an explicit `net` spec and we never allocated.
                if let Some(network) = self.network.as_ref()
                    && let Err(release_err) =
                        network.ipam().release(&vm_key(&id))
                    && !matches!(release_err, IpamError::NotAllocated(_))
                {
                    warn!(
                        "Failed to release IPAM allocation for VM {id} after \
                         create failure: {release_err}"
                    );
                }
                return Err(e);
            }
        };
        let _ = self.cache.insert(id, vm.clone()).is_none();
        Ok(vm)
    }

    /// Stop a virtual machine by its ID
    pub async fn stop(&mut self, id: &VmID) -> Result<(), anyhow::Error> {
        if let Some(vm) = self.cache.get_mut(id) {
            #[cfg(feature = "af-xdp")]
            if let Some(endpoint) = self.xdp.get_mut(id) {
                endpoint
                    .revoke(self.network.as_ref().expect("VM network"))
                    .await?;
            }
            vm.stop()?;
            #[cfg(feature = "af-xdp")]
            if let Some(endpoint) = self.xdp.get_mut(id) {
                endpoint.wait_released();
            }
            Ok(())
        } else {
            Err(anyhow!("Virtual machine with ID '{:?}' not found", id))
        }
    }

    /// Boot a virtual machine, configure the host side of its TAP, and
    /// return the address of its guest auraed. If the TAP configuration
    /// fails, the VM is deleted again. The caller must hold the lock on
    /// this cache for the whole call. Otherwise a concurrent `delete` can
    /// recycle the address of this VM before its TAP is configured.
    pub async fn start(&mut self, id: &VmID) -> Result<String, anyhow::Error> {
        #[cfg(feature = "af-xdp")]
        if self
            .cache
            .get(id)
            .and_then(|vm| vm.vm.net.first())
            .is_some_and(|net| net.xdp_iface.is_some())
        {
            return self.start_xdp(id).await;
        }
        let Some(vm) = self.cache.get_mut(id) else {
            return Err(anyhow!(
                "Virtual machine with ID '{:?}' not found",
                id
            ));
        };
        let endpoint = tap_endpoint(vm)?;
        vm.start()?;
        let address = vm.auraed_address().map(|a| a.to_string());

        if let Some((network, endpoint)) = self.network.as_ref().zip(endpoint)
            && let Err(e) = network
                .configure_tap_endpoint(
                    &endpoint.tap,
                    endpoint.host_ip,
                    endpoint.delegated,
                )
                .await
        {
            error!(
                "Failed to configure TAP endpoint for VM {id}: {e}. \
                 Tearing down."
            );
            return Err(match self.delete(id).await {
                Ok(()) => anyhow!("Failed to configure TAP endpoint: {e}"),
                Err(cleanup) => anyhow!(
                    "Failed to configure TAP endpoint: {e}; rollback also \
                     failed and VM state was retained for retry: {cleanup}"
                ),
            });
        }

        Ok(address.unwrap_or_default())
    }

    #[cfg(feature = "af-xdp")]
    async fn start_xdp(&mut self, id: &VmID) -> Result<String, anyhow::Error> {
        let vm = self.cache.get_mut(id).expect("VM exists");
        vm.ensure_startable()?;
        let net = vm.vm.net.first().expect("AF_XDP NIC").clone();
        let network = self
            .network
            .as_ref()
            .ok_or_else(|| anyhow!("VM networking unavailable"))?;
        if !self.xdp.contains_key(id) {
            let _ = self.xdp.insert(id.clone(), XdpEndpoint::new(&net)?);
        }
        let endpoint = self.xdp.get_mut(id).expect("AF_XDP lease");
        let resource = match endpoint.prepare(network, &net).await {
            Ok(resource) => resource,
            Err(error) => {
                // No boot request owns this generation. Keep the down pair
                // and address for a retry, including deferred-kernel EBUSY.
                endpoint.revoke(network).await.map_err(|cleanup| anyhow!(
                    "{error:#}; AF_XDP preparation rollback retained state: {cleanup:#}"
                ))?;
                endpoint.wait_released();
                return Err(error);
            }
        };
        match vm.start_with_resources([(net.id, resource)].into()) {
            Ok(()) => Ok(vm
                .auraed_address()
                .map(|address| address.to_string())
                .unwrap_or_default()),
            Err(error) => {
                // Every boot error, including a lost response, takes the same
                // revoke → VMM exit/join → fence → lease release path.
                match self.delete(id).await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(anyhow!(
                        "{error:#}; AF_XDP rollback retained state for retry: {cleanup:#}"
                    )),
                }
            }
        }
    }

    /// Delete a virtual machine by its ID
    pub async fn delete(&mut self, id: &VmID) -> Result<(), anyhow::Error> {
        let (endpoint, leaked_ip) = {
            let Some(vm) = self.cache.get_mut(id) else {
                return Err(anyhow!(
                    "Virtual machine with ID '{:?}' not found",
                    id
                ));
            };
            let endpoint = tap_endpoint(vm)?;
            let leaked_ip = vm.vm.net.first().map(|n| n.guest_ip_v6);
            #[cfg(feature = "af-xdp")]
            if vm.vm.net.first().is_some_and(|net| net.xdp_iface.is_some()) {
                if let Some(xdp) = self.xdp.get_mut(id) {
                    xdp.revoke(self.network.as_ref().expect("VM network"))
                        .await?;
                }
                vm.terminate()?;
                if let Some(xdp) = self.xdp.get_mut(id) {
                    xdp.wait_released();
                    xdp.destroy(self.network.as_ref().expect("VM network"))
                        .await?;
                }
            } else {
                vm.delete()?;
            }
            #[cfg(not(feature = "af-xdp"))]
            vm.delete()?;
            (endpoint, leaked_ip)
        };

        // Cloud Hypervisor has confirmed deletion, so the TAP no longer
        // exists and its nftables source binding can be removed safely.
        if let Some(network) = self.network.as_ref() {
            if let Some(endpoint) = endpoint {
                network.destroy_tap_endpoint(&endpoint.tap).await?;
            }

            // Release only after VM deletion and source-filter cleanup.
            // NotAllocated is expected for an explicit caller-supplied net.
            match network.ipam().release(&vm_key(id)) {
                Ok(_) | Err(IpamError::NotAllocated(_)) => {}
                Err(e) => {
                    let leaked = leaked_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "<unknown>".into());
                    return Err(anyhow!(
                        "Failed to release IPAM allocation for VM {id} \
                         (IP {leaked} retained): {e}"
                    ));
                }
            }
        }

        let _ = self.cache.remove(id);
        #[cfg(feature = "af-xdp")]
        let _ = self.xdp.remove(id);
        Ok(())
    }

    /// List all virtual machines
    pub fn list(&self) -> Vec<VirtualMachine> {
        self.cache.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// `aurae_kernel_args` emits exactly the two `aurae.*=` args the
    /// guest's pid1 expects, in a stable order.
    #[test]
    fn aurae_kernel_args_emits_expected_two_args() {
        let allocation = Allocation {
            host_ip: Ipv6Addr::new(0xfd00, 0xae, 0, 0, 0, 0, 0, 0),
            delegated: Ipv6Net::new(
                Ipv6Addr::new(0xfd00, 0xae, 0, 0, 0, 0, 0, 1),
                128,
            )
            .unwrap(),
            guest_ip: Ipv6Addr::new(0xfd00, 0xae, 0, 0, 0, 0, 0, 1),
        };

        let args = aurae_kernel_args(&allocation);
        assert_eq!(
            args,
            [
                "aurae.prefix_v6=fd00:ae::1/128".to_string(),
                "aurae.gw_v6=fd00:ae::".to_string(),
            ]
        );
    }
}
