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

/// The host-side endpoint of a VM's routed TAP, extracted from its
/// [`NetSpec`] after boot. The caller hands this to
/// [`Network::configure_tap_endpoint`] *without* holding the
/// [`VirtualMachines`] lock, so the multi-second link-up wait doesn't
/// serialize unrelated VM operations.
#[derive(Debug, Clone)]
pub(crate) struct TapEndpoint {
    pub tap: String,
    pub host_ip: Ipv6Addr,
    pub delegated: Ipv6Net,
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

    /// Boot a virtual machine by its ID and return the host-side TAP
    /// endpoint that still needs configuring, if any.
    ///
    /// This performs only the synchronous Cloud Hypervisor boot call, so
    /// callers can hold the [`VirtualMachines`] lock for the (brief)
    /// duration of this method and then drop it before configuring the TAP
    /// endpoint — which involves a multi-second link-up wait we don't want
    /// to serialize all VM operations behind.
    ///
    /// Returns `Ok(None)` when the VM has no TAP to configure (e.g. it was
    /// created with an explicit `net` spec without one). On configuration
    /// failure the caller is expected to call [`Self::rollback_failed_start`].
    pub fn start_boot(
        &mut self,
        id: &VmID,
    ) -> Result<Option<TapEndpoint>, anyhow::Error> {
        if self.network.is_none() {
            return Err(anyhow!(
                "VM networking is unavailable on this daemon — refusing start"
            ));
        }

        let Some(vm) = self.cache.get_mut(id) else {
            return Err(anyhow!(
                "Virtual machine with ID '{:?}' not found",
                id
            ));
        };

        vm.start()?;

        let Some(net) = vm.vm.net.first() else {
            return Ok(None);
        };
        let Some(tap) = net.tap.clone() else {
            return Ok(None);
        };
        let delegated = Ipv6Net::new(net.guest_ip_v6, net.prefix_len_v6)
            .map_err(|e| anyhow!("Invalid delegated prefix on NetSpec: {e}"))?;

        Ok(Some(TapEndpoint { tap, host_ip: net.host_ip_v6, delegated }))
    }

    /// Roll back a VM whose host-side TAP configuration failed after boot:
    /// stop + delete it, drop it from the cache, and release its IPAM slot.
    /// Best-effort — every step is logged rather than propagated, since the
    /// caller is already returning the original start failure.
    pub fn rollback_failed_start(&mut self, id: &VmID) {
        if let Some(vm) = self.cache.get_mut(id) {
            let _ = vm.stop();
            let _ = vm.delete();
        }
        let _ = self.cache.remove(id);
        if let Some(network) = self.network.as_ref()
            && let Err(release_err) = network.ipam().release(&vm_key(id))
            && !matches!(release_err, IpamError::NotAllocated(_))
        {
            warn!(
                "Failed to release IPAM allocation for {id} after start \
                 failure: {release_err}"
            );
        }
    }

    /// Address of a VM's guest auraed socket, if the VM is in the cache.
    pub fn guest_socket(&self, id: &VmID) -> Option<String> {
        self.cache.get(id).and_then(|vm| vm.tap()).map(|s| s.to_string())
    }

    /// Delete a virtual machine by its ID
    pub fn delete(&mut self, id: &VmID) -> Result<(), anyhow::Error> {
        if let Some(vm) = self.cache.get_mut(id) {
            vm.delete()?;
            let leaked_ip =
                vm.vm.net.first().map(|n| n.guest_ip_v6.to_string());
            let _ = self.cache.remove(id);
            // Release the IP address back to IPAM for reuse. Ignore
            // NotAllocated, which is expected when the VM was created
            // with an explicit `net` spec (no IPAM reservation).
            if let Some(network) = self.network.as_ref() {
                match network.ipam().release(&vm_key(id)) {
                    Ok(_) => {}
                    Err(IpamError::NotAllocated(_)) => {}
                    Err(e) => {
                        let leaked =
                            leaked_ip.as_deref().unwrap_or("<unknown>");
                        error!(
                            "Failed to release IPAM allocation for VM {id} \
                             (IP {leaked} leaked until daemon restart): {e}"
                        );
                    }
                }
            }
            Ok(())
        } else {
            Err(anyhow!("Virtual machine with ID '{:?}' not found", id))
        }
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
