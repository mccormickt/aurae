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

#[derive(Debug, Default)]
pub struct VirtualMachine {
    id: String,
    name: String,
    spec: VirtualMachineSpec,
    state: VmState,
}

#[derive(Debug, Default)]
pub struct VirtualMachineSpec {
    instance_info: InstanceInfo,
    vm_resources: VmResources,
    vmm: Option<Arc<Mutex<Vmm>>>,
}

impl VirtualMachine {
    pub fn new(name: String, kernel_image_path: String, rootfs_path: String, vcpus: u32, memory_mb: u32) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let instance_info = InstanceInfo {
            id: id.clone(),
            app_name: name.clone(),
            state: VmState::NotStarted,
            vmm_version: "".to_string(),
        };

        let config = format!(
            r#"{{
                "boot-source": {{
                    "kernel_image_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
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
                        "host_dev_name": "aurae0"
                    }}
                ],
                "mmds-config": {{
                    "version": "V2",
                    "ipv4_address": "169.254.42.2",
                    "network_interfaces": ["eth0"]
                }}
            }}"#,
            kernel_image_path,
            rootfs_path,
            vcpus,
            memory_mb,
        );

        let vm_resources =
            VmResources::from_json(config.as_str(), &instance_info, 4096, None)
                .expect("creating vm resources");

        Self { id, name, spec: VirtualMachineSpec { instance_info, vm_resources, vmm: None }, state: VmState::NotStarted }
    }
    pub fn allocate(&mut self, event_manager: &mut EventManager) -> Result<(), FcExitCode> {
        let VmState::NotStarted = &self.state else {
            return Err(FcExitCode::Ok);
        };

        // Initialize the VM
        let (res, vm) =
            build_microvm(
                event_manager,
                &self.spec.instance_info,
                &self.spec.vm_resources,
            ).expect("building microvm");
        self.spec.vmm = vm;

        info!("Started vm {} with id {} ", self.name, self.id);
        debug!(
            "cpu: {} memory: {}",
            res.vm_config().vcpu_count,
            res.vm_config().mem_size_mib
        );

        Ok(())
    }
}

fn build_microvm(
    event_manager: &mut EventManager,
    instance_info: &InstanceInfo,
    vm_resources: &VmResources,
) -> Result<Arc<Mutex<Vmm>>, FcExitCode> {
    let seccomp_filters = seccomp_filters::get_filters(SeccompConfig::Advanced)
        .expect("setting seccomp filters for VM");

    // Build microvm from configuration
    let vmm = vmm::builder::build_microvm_for_boot(
        instance_info,
        vm_resources,
        event_manager,
        &seccomp_filters,
    ).map_err(|err| {
        error!("Building VMM failed: {:?}", err);
        FcExitCode::BadConfiguration
    })?;

    // Pause VM after creation
    // TODO: Allow for us to create a VM without starting it as firecracker doesn't seem to
    vmm.lock().unwrap().pause_vm().expect("pausing allocated vm");
    info!("Successfully built microvm");

    Ok(vmm)
}

#[cfg(test)]
mod test {
    use vmm::EventManager;

    use crate::vms::vm::VirtualMachine;

    #[test]
    fn test_vm_allocate() {
        let mut vm = VirtualMachine::new(
            "aurae-vm-test".to_string(),
            "/home/jan0ski/aurae-runtime/aurae/auraed/hack/hello-vmlinux.bin".to_string(),
            "/home/jan0ski/aurae-runtime/aurae/auraed/hack/hello-rootfs.ext4".to_string(),
            1,
            2048,
        );
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        assert!(vm.allocate(&mut event_manager).is_ok())
    }
}