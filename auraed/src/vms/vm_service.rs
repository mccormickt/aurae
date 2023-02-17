use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tonic::Request;
use vmm::EventManager;

use proto::vms::{
    vm_service_server, VmServiceAllocateRequest,
    VmServiceAllocateResponse, VmServiceFreeRequest, VmServiceFreeResponse,
    VmServiceStartRequest, VmServiceStartResponse, VmServiceStopRequest,
    VmServiceStopResponse,
};

use crate::vms::error::Result;
use crate::vms::vm::VirtualMachine;

type VirtualMachines = HashMap<String, VirtualMachine>;

#[derive(Debug, Clone)]
pub struct VmService {
    vms: Arc<Mutex<VirtualMachines>>,
    event_manager: Arc<Mutex<EventManager>>,
}

#[tonic::async_trait]
impl vm_service_server::VmService for VmService {
    async fn allocate(
        &mut self,
        request: Request<VmServiceAllocateRequest>,
    ) -> Result<VmServiceAllocateResponse> {
        let req = request.into_inner();
        let machine = req.machine.unwrap();
        let root_drive = machine.root_drive.unwrap();

        let vm = self
            .vms.lock().unwrap()
            .entry(machine.id.clone())
            .or_insert_with(||
                VirtualMachine::new(
                    machine.id,
                    machine.kernel_img_path,
                    root_drive.host_path,
                    machine.vcpu_count,
                    machine.mem_size_mb,
                )
            );

        let mut event_manager = self.event_manager.lock().await;
        vm.allocate(&mut event_manager)?;

        Ok(VmServiceAllocateResponse { vm_id: machine.id.clone() })
    }

    async fn free(
        &self,
        _request: Request<VmServiceFreeRequest>,
    ) -> Result<VmServiceFreeResponse> {
        todo!()
    }

    async fn start(
        &self,
        _request: Request<VmServiceStartRequest>,
    ) -> Result<VmServiceStartResponse> {
        todo!()
    }

    async fn stop(
        &self,
        _request: Request<VmServiceStopRequest>,
    ) -> Result<VmServiceStopResponse> {
        todo!()
    }
}
