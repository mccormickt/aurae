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

        Self { cache: Cache::new(), network }
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

            // Reserve a unique TAP name. Cloud Hypervisor creates it on
            // VM start; we just hand it the name.
            let tap_name = network.reserve_tap_name();

            spec.net.push(NetSpec {
                tap: Some(tap_name),
                mac: MacAddr::local_random(),
                host_mac: None,
                host_ip_v6: allocation.host_ip,
                guest_ip_v6: allocation.guest_ip,
                prefix_len_v6: allocation.delegated.prefix_len(),
            });

            spec.kernel_args.extend(aurae_kernel_args(&allocation));
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
    pub fn stop(&mut self, id: &VmID) -> Result<(), anyhow::Error> {
        if let Some(vm) = self.cache.get_mut(id) {
            vm.stop()?;
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
