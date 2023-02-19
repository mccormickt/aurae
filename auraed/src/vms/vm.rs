/* -------------------------------------------------------------------------- *\
 *        Apache 2.0 License Copyright © 2022-2023 The Aurae Authors          *
 *                                                                            *
 *                +--------------------------------------------+              *
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 *                                                                            *
 * -------------------------------------------------------------------------- *
 *                                                                            *
 *   Licensed under the Apache License, Version 2.0 (the "License");          *
 *   you may not use this file except in compliance with the License.         *
 *   You may obtain a copy of the License at                                  *
 *                                                                            *
 *       http://www.apache.org/licenses/LICENSE-2.0                           *
 *                                                                            *
 *   Unless required by applicable law or agreed to in writing, software      *
 *   distributed under the License is distributed on an "AS IS" BASIS,        *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. *
 *   See the License for the specific language governing permissions and      *
 *   limitations under the License.                                           *
 *                                                                            *
\* -------------------------------------------------------------------------- */

use std::sync::{Arc, Mutex};

use tracing::{debug, error, info};
use vmm::{EventManager, FcExitCode, seccomp_filters, Vmm};
use vmm::resources::VmResources;
use vmm::seccomp_filters::SeccompConfig;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};

use crate::vms::error::VmServiceError;

pub type Result<T> = std::result::Result<T, VmServiceError>;

#[derive(Default)]
pub struct VirtualMachine {
    pub id: String,
    pub name: String,
    pub spec: VirtualMachineSpec,
    pub state: VmState,
    vmm: Option<Arc<Mutex<Vmm>>>,
}

#[derive(Default)]
pub struct VirtualMachineSpec {
    pub kernel_image_path: String,
    pub kernel_args: Vec<String>,
    pub rootfs_path: String,
    pub mac_address: String,
    pub host_dev_name: String,
    pub vcpus: u32,
    pub memory_mb: u32,
}

impl VirtualMachine {
    pub fn new(name: String, spec: VirtualMachineSpec) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        Self { id, name, state: VmState::NotStarted, spec, vmm: None }
    }
    pub fn allocate(&mut self) -> Result<()> {
        let VmState::NotStarted = &self.state else {
            return Err(VmServiceError::VmExists { vm_id: self.id.clone() });
        };
        let instance_info = InstanceInfo {
            id: self.id.clone(),
            app_name: self.name.clone(),
            state: VmState::NotStarted,
            vmm_version: "".to_string(),
        };

        let config = format!(
            r#"{{
                "boot-source": {{
                    "kernel_image_path": "{}",
                    "boot_args": "{}"
                }},
                "drives": [
                    {{
                        "drive_id": "rootfs",
                        "path_on_host": "{}",
                        "is_root_device": true,
                        "is_read_only": false
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": {},
                    "mem_size_mib": {},
                    "smt": false
                }},
                "network-interfaces": [
                    {{
                        "iface_id": "eth0",
                        "guest_mac": "{}",
                        "host_dev_name": "{}"
                    }}
                ],
                "vsock": {{
                    "guest_cid": 3,
                    "uds_path": "/run/aurae/aurae.vsock",
                    "vsock_id": "vsock0"
                }},
                "mmds-config": {{
                    "version": "V2",
                    "ipv4_address": "169.254.42.2",
                    "network_interfaces": ["eth0"]
                }}
            }}"#,
            self.spec.kernel_image_path,
            self.spec.kernel_args.join(" "),
            self.spec.rootfs_path,
            self.spec.vcpus,
            self.spec.memory_mb,
            self.spec.mac_address,
            self.spec.host_dev_name,
        );
        let vm_resources =
            VmResources::from_json(config.as_str(), &instance_info, 4096, None)
                .expect("creating vm resources");

        // Initialize the VM
        let mut event_manager =
            EventManager::new().expect("Unable to create EventManager");
        let vmm =
            build_microvm(&mut event_manager, &instance_info, &vm_resources)
                .expect("building microvm");
        self.vmm = Some(vmm);

        info!("Started vm {} with id {} ", self.name, self.id.clone());
        debug!("cpu: {} memory: {}", self.spec.vcpus, self.spec.memory_mb);

        Ok(())
    }

    pub fn free(&mut self) -> Result<()> {
        // TODO: Do we need to free resources? Are there methods for this?
        let vmm = self.vmm.as_ref().expect("retrieve vmm ref to free");
        let vm = vmm.lock().expect("retireve lock for vmm");
        self.stop()
    }

    pub fn start(&mut self) -> Result<()> {
        if self.state == VmState::Running {
            return Ok(());
        }
        let vmm = self.vmm.as_ref().expect("retrieve vmm ref to start");
        let mut vm = vmm.lock().expect("retrieve lock for vmm");
        self.state = VmState::Running;
        match vm.resume_vm() {
            Ok(_) => {
                Ok(())
            }
            Err(_) => {
                Err(VmServiceError::VmNotFound { vm_id: self.id.clone() })
            }
        }
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.state != VmState::Running {
            return Err(VmServiceError::KillError {
                vm_id: self.id.clone(),
                error: "vm is not running".to_string(),
            });
        }
        let vmm = self.vmm.as_ref().expect("retrieve vmm ref to stop");
        vmm.lock().expect("retrieve lock for vmm").stop(FcExitCode::Ok);
        self.state = VmState::NotStarted;
        Ok(())
    }
}

fn build_microvm(
    event_manager: &mut EventManager,
    instance_info: &InstanceInfo,
    vm_resources: &VmResources,
) -> std::result::Result<Arc<Mutex<Vmm>>, FcExitCode> {
    let seccomp_filters = seccomp_filters::get_filters(SeccompConfig::None)
        .expect("setting seccomp filters for VM");

    // Build microvm from configuration
    let vmm = vmm::builder::build_microvm_for_boot(
        instance_info,
        vm_resources,
        event_manager,
        &seccomp_filters,
    )
        .map_err(|err| {
            error!("Building VMM failed: {:?}", err);
            FcExitCode::BadConfiguration
        })?;

    // Pause VM after creation
    // TODO: Allow for us to create a VM without starting it as firecracker doesn't seem to
    vmm.lock()
        .expect("retrieve vmm lock")
        .pause_vm()
        .expect("pausing allocated vm");
    info!("Successfully built microvm");

    Ok(vmm)
}

#[cfg(test)]
mod test {
    use crate::vms::vm::{VirtualMachine, VirtualMachineSpec};

    #[test]
    fn test_vm_allocate() {
        let mut vm = VirtualMachine::new(
            "aurae-vm-test".to_string(),
            VirtualMachineSpec {
                kernel_image_path: "/home/jan0ski/aurae-runtime/aurae/auraed/hack/hello-vmlinux.bin".to_string(),
                kernel_args: vec!["console=ttyS0".to_string(), "reboot=k".to_string(), "panic=1".to_string(), "pci=off".to_string()],
                rootfs_path: "/home/jan0ski/aurae-runtime/aurae/auraed/hack/hello-rootfs.ext4".to_string(),
                mac_address: "deadbeef::1234".to_string(),
                host_dev_name: "aurae0".to_string(),
                vcpus: 1,
                memory_mb: 2048,
            },
        );
        assert!(vm.allocate().is_ok())
    }
}
