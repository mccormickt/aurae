use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use proto::vms::{
    vm_service_server, VmServiceAllocateRequest, VmServiceAllocateResponse,
    VmServiceFreeRequest, VmServiceFreeResponse, VmServiceStartRequest,
    VmServiceStartResponse, VmServiceStopRequest, VmServiceStopResponse,
};

use crate::vms::vm::{VirtualMachine, VirtualMachineSpec};

type VirtualMachines = HashMap<String, VirtualMachine>;
pub type Result<T> = std::result::Result<T, Status>;

#[derive(Clone)]
pub struct VmService {
    vms: Arc<Mutex<VirtualMachines>>,
}

impl VmService {
    pub fn new() -> Self {
        Self { vms: Default::default() }
    }
}

#[tonic::async_trait]
impl vm_service_server::VmService for VmService {
    #[tracing::instrument(skip(self))]
    async fn allocate(
        &self,
        request: Request<VmServiceAllocateRequest>,
    ) -> Result<Response<VmServiceAllocateResponse>> {
        let req = request.into_inner();
        let machine = req.machine.expect("vm allocate from request");
        let root_drive =
            machine.root_drive.expect("vm root drive from request");
        let network_interface = machine
            .network_interfaces
            .first()
            .expect("network interface from request")
            .clone();

        let mut vms = self.vms.lock().await;
        let vm = vms.entry(machine.id.clone()).or_insert_with(|| {
            VirtualMachine::new(
                machine.id.clone(),
                VirtualMachineSpec {
                    kernel_image_path: machine.kernel_img_path,
                    kernel_args: machine.kernel_args,
                    rootfs_path: root_drive.host_path,
                    mac_address: network_interface.mac_address,
                    host_dev_name: network_interface.host_dev_name,
                    vcpus: machine.vcpu_count,
                    memory_mb: machine.mem_size_mb,
                },
            )
        });
        vm.allocate()?;
        Ok(Response::new(VmServiceAllocateResponse { vm_id: machine.id }))
    }

    #[tracing::instrument(skip(self))]
    async fn free(
        &self,
        request: Request<VmServiceFreeRequest>,
    ) -> Result<Response<VmServiceFreeResponse>> {
        let req = request.into_inner();
        let mut vms = self.vms.lock().await;
        let vm = vms.get_mut(req.vm_id.as_str()).expect("retrieving vm");
        vm.free().expect("freeing vm");
        Ok(Response::new(VmServiceFreeResponse {}))
    }

    #[tracing::instrument(skip(self))]
    async fn start(
        &self,
        request: Request<VmServiceStartRequest>,
    ) -> Result<Response<VmServiceStartResponse>> {
        let req = request.into_inner();
        let mut vms = self.vms.lock().await;
        let vm = vms.get_mut(req.vm_id.as_str()).expect("getting vm to start");
        vm.start().expect("starting vm");
        Ok(Response::new(VmServiceStartResponse {}))
    }

    #[tracing::instrument(skip(self))]
    async fn stop(
        &self,
        request: Request<VmServiceStopRequest>,
    ) -> Result<Response<VmServiceStopResponse>> {
        let req = request.into_inner();
        let mut vms = self.vms.lock().await;
        let vm = vms.get_mut(req.vm_id.as_str()).expect("getting vm to stop");
        vm.stop().expect("stopping vm");
        Ok(Response::new(VmServiceStopResponse {}))
    }
}
