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
use crate::vms::manager::Manager;
use anyhow::anyhow;
use net_util::MacAddr;
use std::{
    fmt::{self, Display},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[cfg(target_arch = "x86_64")]
use vmm::vm_config::DebugConsoleConfig;
use vmm::{
    api::ApiAction,
    vm::VmState,
    vm_config::{
        ConsoleConfig, CoreScheduling, CpuFeatures, CpusConfig,
        DEFAULT_DISK_NUM_QUEUES, DEFAULT_DISK_QUEUE_SIZE,
        DEFAULT_MAX_PHYS_BITS, DEFAULT_NET_NUM_QUEUES, DEFAULT_NET_QUEUE_SIZE,
        HotplugMethod, MemoryConfig, PayloadConfig, PciDeviceCommonConfig,
        RngConfig, SerialConfig, VhostMode,
    },
};

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct VmID(String);

impl VmID {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl Display for VmID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct VmSpec {
    pub memory_size: u32,
    pub vcpu_count: u32,
    pub kernel_image_path: PathBuf,
    pub kernel_args: Vec<String>,
    pub mounts: Vec<MountSpec>,
    pub net: Vec<NetSpec>,
}

impl From<VmSpec> for vmm::vm_config::VmConfig {
    fn from(spec: VmSpec) -> Self {
        vmm::vm_config::VmConfig {
            cpus: CpusConfig {
                boot_vcpus: spec.vcpu_count,
                max_vcpus: spec.vcpu_count,
                topology: None,
                kvm_hyperv: false,
                max_phys_bits: DEFAULT_MAX_PHYS_BITS,
                affinity: None,
                features: CpuFeatures::default(),
                nested: false,
                core_scheduling: CoreScheduling::default(),
            },
            memory: MemoryConfig {
                size: u64::from(spec.memory_size) << 20,
                mergeable: false,
                hotplug_method: HotplugMethod::default(),
                hotplug_size: None,
                hotplugged_size: None,
                shared: false,
                hugepages: false,
                hugepage_size: None,
                prefault: false,
                zones: None,
                thp: false,
            },
            payload: Some(PayloadConfig {
                firmware: None,
                kernel: Some(spec.kernel_image_path),
                cmdline: Some(spec.kernel_args.join(" ")),
                initramfs: None,
            }),
            rate_limit_groups: None,
            disks: Some(spec.mounts.into_iter().map(Into::into).collect()),
            net: Some(spec.net.into_iter().map(Into::into).collect()),
            rng: RngConfig::default(),
            balloon: None,
            generic_vhost_user: None,
            fs: None,
            pmem: None,
            serial: SerialConfig::default(),
            console: ConsoleConfig::default(),
            #[cfg(target_arch = "x86_64")]
            debug_console: DebugConsoleConfig::default(),
            devices: None,
            user_devices: None,
            vdpa: None,
            vsock: None,
            pvpanic: false,
            iommu: false,
            numa: None,
            watchdog: false,
            pci_segments: None,
            platform: None,
            tpm: None,
            preserved_fds: None,
            landlock_enable: true,
            landlock_rules: None,
        }
    }
}

/// Network configuration for a VM.
///
/// Carries the host-side TAP gateway address (used by Cloud Hypervisor to
/// configure the host side of the TAP) and the guest-side address +
/// delegated prefix (passed via kernel cmdline so pid1 inside the guest
/// configures eth0).
///
/// The host-side address is always /128 — the routed point-to-link shape —
/// even when the device prefix is wider, because the host's view of the TAP
/// is just one address. Networking is IPv6-only.
#[derive(Debug, Clone)]
pub struct NetSpec {
    /// TAP device name (CH creates it if it doesn't exist).
    pub tap: Option<String>,
    /// MAC address for the VM's virtual NIC.
    pub mac: MacAddr,
    /// Optional host MAC address.
    pub host_mac: Option<MacAddr>,
    /// Host-side IPv6 address (TAP gateway).
    pub host_ip_v6: Ipv6Addr,
    /// Guest-side IPv6 address.
    pub guest_ip_v6: Ipv6Addr,
    /// Prefix length of the guest's delegated block. /128 for a VM hosted
    /// inside a cell (sub-delegated out of the cell's block); /112 for a VM
    /// the host daemon owns directly (the default device prefix). The guest
    /// binds `guest_ip_v6` and the host routes the whole block to the TAP.
    pub prefix_len_v6: u8,
}

impl From<NetSpec> for vmm::vm_config::NetConfig {
    fn from(spec: NetSpec) -> Self {
        // `ip`/`mask` stay `None` so Cloud Hypervisor leaves TAP addressing
        // alone (`open_tap` only calls `set_ip_addr` when an ip is given).
        // auraed owns the TAP's host address: it must be added with
        // IFA_F_NODAD, because an address CH adds undergoes DAD, sits
        // *tentative* on the carrier-up TAP, and a tentative address is
        // rejected as the dev route's preferred source with EINVAL. The
        // guest learns its own addressing from the `aurae.*` kernel args,
        // not from this field.
        vmm::vm_config::NetConfig {
            pci_common: PciDeviceCommonConfig::default(),
            tap: spec.tap,
            ip: None,
            mask: None,
            mac: spec.mac,
            host_mac: spec.host_mac,
            mtu: None,
            num_queues: DEFAULT_NET_NUM_QUEUES,
            queue_size: DEFAULT_NET_QUEUE_SIZE,
            vhost_user: false,
            vhost_socket: None,
            vhost_mode: VhostMode::default(),
            fds: None,
            rate_limiter_config: None,
            offload_tso: false,
            offload_ufo: false,
            offload_csum: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MountSpec {
    pub host_path: PathBuf,
    pub read_only: bool,
}

impl From<MountSpec> for vmm::vm_config::DiskConfig {
    fn from(spec: MountSpec) -> Self {
        vmm::vm_config::DiskConfig {
            pci_common: PciDeviceCommonConfig::default(),
            path: Some(spec.host_path),
            readonly: spec.read_only,
            direct: false,
            num_queues: DEFAULT_DISK_NUM_QUEUES,
            queue_size: DEFAULT_DISK_QUEUE_SIZE,
            vhost_user: false,
            vhost_socket: None,
            rate_limit_group: None,
            rate_limiter_config: None,
            disable_io_uring: false,
            disable_aio: false,
            serial: None,
            queue_affinity: None,
            backing_files: false,
            sparse: true,
            image_type: Default::default(),
            lock_granularity: Default::default(),
        }
    }
}

#[derive(Clone)]
pub struct VirtualMachine {
    pub id: VmID,
    pub vm: VmSpec,
    pub status: VmStatus,
    manager: Arc<Mutex<Manager>>,
    deleted: bool,
}

impl fmt::Debug for VirtualMachine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VirtualMachine {{ id: {:?}, vm: {:?} }}", self.id, self.vm)
    }
}

#[derive(Debug, Clone)]
pub struct VmStatus(VmState);

impl Display for VmStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl VirtualMachine {
    pub fn new(id: VmID, spec: VmSpec) -> Result<Self, anyhow::Error> {
        let mut manager = Manager::new()?;
        manager.start()?;

        if let Some(sender) = &manager.sender {
            vmm::api::VmCreate
                .send(
                    manager.events.try_clone()?,
                    sender.clone(),
                    Box::new(spec.clone().into()),
                )
                .map_err(|e| anyhow!("Failed to send create request: {e}"))?;
        } else {
            return Err(anyhow!("Virtual machine manager not initialized"));
        }

        Ok(VirtualMachine {
            id,
            vm: spec,
            status: VmStatus(VmState::Created),
            manager: Arc::new(Mutex::new(manager)),
            deleted: false,
        })
    }

    pub fn start(&mut self) -> Result<(), anyhow::Error> {
        if self.deleted {
            return Err(anyhow!("Virtual machine has been deleted"));
        }
        if let VmState::Running = self.status.0 {
            return Err(anyhow!("Virtual machine already running"));
        }
        let manager = self
            .manager
            .lock()
            .map_err(|_| anyhow!("Failed to aquire lock for vm manager"))?;

        if let Some(sender) = &manager.sender {
            let _ = vmm::api::VmBoot
                .send(manager.events.try_clone()?, sender.clone(), ())
                .map_err(|e| anyhow!("Failed to send start request: {e}"))?;
            self.status = VmStatus(VmState::Running);
        } else {
            return Err(anyhow!("Virtual machine manager not initialized"))?;
        }

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), anyhow::Error> {
        if self.deleted {
            return Err(anyhow!("Virtual machine has been deleted"));
        }
        if let VmState::Shutdown = self.status.0 {
            return Err(anyhow!("Virtual machine already stopped"));
        }
        let manager = self
            .manager
            .lock()
            .map_err(|_| anyhow!("Failed to aquire lock for vm manager"))?;

        if let Some(sender) = &manager.sender {
            let _ = vmm::api::VmShutdown
                .send(manager.events.try_clone()?, sender.clone(), ())
                .map_err(|e| anyhow!("Failed to send stop request: {e}"))?;
            self.status = VmStatus(VmState::Shutdown);
        } else {
            return Err(anyhow!("Virtual machine manager not initialized"));
        }

        Ok(())
    }

    pub fn delete(&mut self) -> Result<(), anyhow::Error> {
        if self.deleted {
            return Ok(());
        }
        if self.status.0 != VmState::Shutdown {
            self.stop()?;
        };
        let manager = self
            .manager
            .lock()
            .map_err(|_| anyhow!("Failed to aquire lock for vm manager"))?;

        if let Some(sender) = &manager.sender {
            let _ = vmm::api::VmDelete
                .send(manager.events.try_clone()?, sender.clone(), ())
                .map_err(|e| anyhow!("Failed to send destroy request: {e}"))?;
            self.deleted = true;
            return Ok(());
        }
        Err(anyhow!("Virtual machine manager not initialized"))
    }

    /// Socket address for connecting to the auraed instance in this VM.
    /// Returns the VM's IPv6 address (ULA) on the well-known auraed port.
    pub fn tap(&self) -> Option<SocketAddr> {
        let net = self.vm.net.first()?;
        Some(SocketAddr::V6(SocketAddrV6::new(net.guest_ip_v6, 8080, 0, 0)))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::path::PathBuf;

    use net_util::MacAddr;

    use super::{MountSpec, NetSpec, VirtualMachine, VmID, VmSpec};

    #[test]
    #[ignore]
    fn test_create_vm() {
        let id = VmID::new("test_vm");
        let host_v6 = Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 0);
        let guest_v6 = Ipv6Addr::new(0xfd00, 0x00ae, 0, 0, 0, 0, 0, 1);

        let spec = VmSpec {
            memory_size: 1024,
            vcpu_count: 4,
            kernel_image_path: PathBuf::from(
                "/var/lib/aurae/vm/kernel/vmlinux.bin",
            ),
            kernel_args: vec![
                "console=hvc0".to_string(),
                "root=/dev/vda1".to_string(),
                format!("aurae.prefix_v6={guest_v6}/128"),
                format!("aurae.gw_v6={host_v6}"),
            ],
            mounts: vec![MountSpec {
                host_path: PathBuf::from("/var/lib/aurae/vm/image/disk.raw"),
                read_only: false,
            }],
            net: vec![NetSpec {
                tap: Some("tap0".to_string()),
                mac: MacAddr::local_random(),
                host_mac: None,
                host_ip_v6: host_v6,
                guest_ip_v6: guest_v6,
                prefix_len_v6: 128,
            }],
        };

        let mut vm = VirtualMachine::new(id.clone(), spec).unwrap();
        assert_eq!(vm.id, id);

        assert!(vm.start().is_ok(), "{:?}", vm);

        std::thread::sleep(std::time::Duration::from_secs(10));
        assert!(vm.stop().is_ok(), "{:?}", vm);

        std::thread::sleep(std::time::Duration::from_secs(5));
        assert!(vm.delete().is_ok(), "{:?}", vm);
    }

    fn sample_net_spec() -> NetSpec {
        NetSpec {
            tap: Some("vm-7".to_string()),
            mac: MacAddr::local_random(),
            host_mac: None,
            host_ip_v6: Ipv6Addr::new(0xfd00, 0xae, 0, 0, 0, 0, 0, 0),
            guest_ip_v6: Ipv6Addr::new(0xfd00, 0xae, 0, 0, 0, 0, 0, 1),
            prefix_len_v6: 128,
        }
    }

    fn sample_vm_spec() -> VmSpec {
        VmSpec {
            memory_size: 512,
            vcpu_count: 2,
            kernel_image_path: PathBuf::from("/k/vmlinux.bin"),
            kernel_args: vec!["console=hvc0".into()],
            mounts: vec![
                MountSpec {
                    host_path: PathBuf::from("/disks/root.raw"),
                    read_only: true,
                },
                MountSpec {
                    host_path: PathBuf::from("/disks/data.raw"),
                    read_only: false,
                },
            ],
            net: vec![sample_net_spec()],
        }
    }

    /// `NetSpec` → `vmm::vm_config::NetConfig` must NOT hand the host-side
    /// IP to Cloud Hypervisor: CH would configure it on the TAP itself,
    /// without IFA_F_NODAD, and the resulting *tentative* address makes the
    /// kernel reject auraed's dev route (tentative preferred source →
    /// EINVAL). TAP addressing belongs to auraed alone.
    #[test]
    fn net_spec_to_net_config_leaves_tap_addressing_to_auraed() {
        let spec = sample_net_spec();
        let cfg: vmm::vm_config::NetConfig = spec.into();

        assert_eq!(cfg.ip, None);
        assert_eq!(cfg.mask, None);
        assert_eq!(cfg.tap.as_deref(), Some("vm-7"));
    }

    /// `MountSpec` → `DiskConfig` carries the host path and `read_only`
    /// flag through unchanged.
    #[test]
    fn mount_spec_to_disk_config_preserves_path_and_readonly() {
        let spec =
            MountSpec { host_path: PathBuf::from("/x/y.raw"), read_only: true };
        let cfg: vmm::vm_config::DiskConfig = spec.into();
        assert_eq!(cfg.path.as_deref(), Some(std::path::Path::new("/x/y.raw")));
        assert!(cfg.readonly);
    }

    /// `VmSpec` → `VmConfig` round-trips CPU, memory, kernel, payload,
    /// and disk count.
    #[test]
    fn vm_spec_to_vm_config_round_trip_preserves_core_fields() {
        let spec = sample_vm_spec();
        let cfg: vmm::vm_config::VmConfig = spec.into();

        assert_eq!(cfg.cpus.boot_vcpus, 2);
        assert_eq!(cfg.cpus.max_vcpus, 2);
        // memory_size is in MiB; VmConfig stores bytes (size << 20).
        assert_eq!(cfg.memory.size, 512u64 << 20);

        let payload = cfg.payload.as_ref().expect("payload");
        assert_eq!(
            payload.kernel.as_deref(),
            Some(std::path::Path::new("/k/vmlinux.bin"))
        );
        assert_eq!(payload.cmdline.as_deref(), Some("console=hvc0"));

        let disks = cfg.disks.as_ref().expect("disks");
        assert_eq!(disks.len(), 2);
        // Root drive is read-only in the sample spec; data drive isn't.
        assert!(disks[0].readonly);
        assert!(!disks[1].readonly);

        let nets = cfg.net.as_ref().expect("net");
        assert_eq!(nets.len(), 1);
        assert!(cfg.landlock_enable);
    }

    #[test]
    fn memory_size_conversion_widens_before_shifting() {
        let mut spec = sample_vm_spec();
        spec.memory_size = u32::MAX;
        let cfg: vmm::vm_config::VmConfig = spec.into();
        assert_eq!(cfg.memory.size, u64::from(u32::MAX) << 20);
    }
}
