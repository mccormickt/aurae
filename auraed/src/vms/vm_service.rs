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

use anyhow::anyhow;
use client::vms::vm_service::VmServiceClient;
use proto::vms::{
    VirtualMachineSummary, VmServiceAllocateRequest, VmServiceAllocateResponse,
    VmServiceFreeRequest, VmServiceFreeResponse, VmServiceListRequest,
    VmServiceListResponse, VmServiceStartRequest, VmServiceStartResponse,
    VmServiceStopRequest, VmServiceStopResponse, vm_service_server,
};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::error;
use validation::ValidatedField;

use crate::cells::cell_service::cells::{CellName, Cells};
use crate::init::network::Network;

use super::{
    error::{Result, VmServiceError},
    proxy::proxy_to_cell,
    virtual_machine::{MountSpec, VmID, VmSpec},
    virtual_machines::VirtualMachines,
};

/// VmService struct manages the lifecycle of virtual machines.
#[derive(Debug, Clone)]
pub struct VmService {
    vms: Arc<Mutex<VirtualMachines>>,
    /// Shared host networking. `None` when VM networking could not be
    /// set up (non-daemon contexts, netlink failed). Allocation is
    /// refused in that state.
    network: Option<Network>,
    /// Shared with `CellService` so `cell_name`-scoped requests can be
    /// proxied into a nested auraed.
    cells: Arc<Mutex<Cells>>,
    // TODO: ObserveService
}

impl VmService {
    /// Allocates a new instance of VmService.
    ///
    /// `network` is the daemon's `Network` handle (which owns the IPAM
    /// allocator). Pass `None` from non-Daemon contexts and from hosts
    /// where network setup failed; VM allocation is refused in that
    /// state.
    ///
    /// `cells` is shared with [`crate::cells::CellService`] so that
    /// `cell_name`-scoped VM RPCs can look up the target cell's client
    /// socket and proxy the request.
    pub fn new(network: Option<Network>, cells: Arc<Mutex<Cells>>) -> Self {
        Self {
            vms: Arc::new(Mutex::new(VirtualMachines::new(network.clone()))),
            network,
            cells,
        }
    }

    #[tracing::instrument(skip(self))]
    async fn allocate(
        &self,
        request: VmServiceAllocateRequest,
    ) -> Result<VmServiceAllocateResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let mut req = request;
            req.cell_name = None;
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                req,
                |client, req| async move {
                    VmServiceClient::allocate(&client, req)
                        .await
                        .map(|r| r.into_inner())
                },
            )
            .await;
        }

        // Refuse early if this auraed has no Network (a non-daemon context,
        // a cell without `isolate_network`, or a host where netlink/
        // forwarding setup failed). A nested auraed inside an isolated cell
        // *does* have one — seeded from the cell's delegated prefix — so it
        // hosts the proxied VM locally from here.
        if self.network.is_none() {
            return Err(VmServiceError::NetworkingUnavailable);
        }

        let mut vms = self.vms.lock().await;

        let Some(vm) = request.machine else {
            return Err(VmServiceError::MissingMachineConfig {});
        };

        let id = VmID::new(vm.id);
        let Some(root_drive) = vm.root_drive else {
            return Err(VmServiceError::MissingRootDrive { id: id.clone() });
        };

        let mut mounts = vec![MountSpec {
            host_path: PathBuf::from(root_drive.image_path.as_str()),
            read_only: root_drive.read_only,
        }];
        mounts.extend(vm.drive_mounts.into_iter().map(|m| MountSpec {
            host_path: PathBuf::from(m.image_path.as_str()),
            read_only: m.read_only,
        }));

        let spec = VmSpec {
            memory_size: vm.mem_size_mb,
            vcpu_count: vm.vcpu_count,
            kernel_image_path: PathBuf::from(vm.kernel_img_path.as_str()),
            kernel_args: vm.kernel_args,
            mounts,
            net: vec![],
        };

        let vm = vms.create(id.clone(), spec).map_err(|e| {
            VmServiceError::FailedToAllocateError { id, source: e }
        })?;

        Ok(VmServiceAllocateResponse { vm_id: vm.id.to_string() })
    }

    #[tracing::instrument(skip(self))]
    async fn free(
        &self,
        request: VmServiceFreeRequest,
    ) -> Result<VmServiceFreeResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let mut req = request;
            req.cell_name = None;
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                req,
                |client, req| async move {
                    VmServiceClient::free(&client, req)
                        .await
                        .map(|r| r.into_inner())
                },
            )
            .await;
        }

        let id = VmID::new(request.vm_id);

        let mut vms = self.vms.lock().await;
        vms.delete(&id)
            .map_err(|e| VmServiceError::FailedToFreeError { id, source: e })?;

        Ok(VmServiceFreeResponse {})
    }

    #[tracing::instrument(skip(self))]
    async fn start(
        &self,
        request: VmServiceStartRequest,
    ) -> Result<VmServiceStartResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let mut req = request;
            req.cell_name = None;
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                req,
                |client, req| async move {
                    VmServiceClient::start(&client, req)
                        .await
                        .map(|r| r.into_inner())
                },
            )
            .await;
        }

        let id = VmID::new(request.vm_id);

        // Phase 1: boot the VM under the lock and extract the host-side TAP
        // to configure. `start_boot` does no awaiting, so the lock is held
        // only for the (fast) Cloud Hypervisor boot call.
        let tap_endpoint = {
            let mut vms = self.vms.lock().await;
            vms.start_boot(&id).map_err(|e| {
                VmServiceError::FailedToStartError { id: id.clone(), source: e }
            })?
        };

        // Phase 2: configure the host side of the TAP *without* holding the
        // VMs lock. This waits for the device to appear and brings the link
        // up (a multi-second operation); serializing all VM RPCs behind it
        // would needlessly block unrelated VMs.
        if let Some(endpoint) = tap_endpoint {
            let network = self
                .network
                .as_ref()
                .ok_or(VmServiceError::NetworkingUnavailable)?;
            if let Err(e) = network
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
                // Phase 3: roll back under the lock — stop + delete the VM,
                // drop it from the cache, release its IPAM slot.
                self.vms.lock().await.rollback_failed_start(&id);
                return Err(VmServiceError::FailedToStartError {
                    id,
                    source: anyhow!("Failed to configure TAP endpoint: {e}"),
                });
            }
        }

        // Phase 4: read back the guest auraed address.
        let addr = self.vms.lock().await.guest_socket(&id).unwrap_or_default();

        Ok(VmServiceStartResponse { auraed_address: addr })
    }

    #[tracing::instrument(skip(self))]
    async fn stop(
        &self,
        request: VmServiceStopRequest,
    ) -> Result<VmServiceStopResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let mut req = request;
            req.cell_name = None;
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                req,
                |client, req| async move {
                    VmServiceClient::stop(&client, req)
                        .await
                        .map(|r| r.into_inner())
                },
            )
            .await;
        }

        let id = VmID::new(request.vm_id);

        let mut vms = self.vms.lock().await;
        vms.stop(&id)
            .map_err(|e| VmServiceError::FailedToStopError { id, source: e })?;

        Ok(VmServiceStopResponse {})
    }

    #[tracing::instrument(skip(self))]
    async fn list(
        &self,
        request: VmServiceListRequest,
    ) -> Result<VmServiceListResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let mut req = request;
            req.cell_name = None;
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                req,
                |client, req| async move {
                    VmServiceClient::list(&client, req)
                        .await
                        .map(|r| r.into_inner())
                },
            )
            .await;
        }

        let vms = self.vms.lock().await;
        Ok(VmServiceListResponse {
            machines: vms
                .list()
                .iter()
                .map(|m| VirtualMachineSummary {
                    id: m.id.to_string(),
                    mem_size_mb: m.vm.memory_size,
                    vcpu_count: m.vm.vcpu_count,
                    kernel_img_path: m
                        .vm
                        .kernel_image_path
                        .to_string_lossy()
                        .to_string(),
                    root_dir_path: m.vm.mounts[0]
                        .host_path
                        .to_string_lossy()
                        .to_string(),
                    auraed_address: m
                        .tap()
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                    status: m.status.to_string(),
                })
                .collect(),
        })
    }

    /// Stop all VMs (host-scoped only).
    #[tracing::instrument(skip(self))]
    pub async fn stop_all(&self) -> Result<()> {
        for vm in self.list(VmServiceListRequest::default()).await?.machines {
            let _ = self
                .stop(VmServiceStopRequest { vm_id: vm.id, cell_name: None })
                .await?;
        }
        Ok(())
    }

    /// Free all VMs (host-scoped only).
    #[tracing::instrument(skip(self))]
    pub async fn free_all(&self) -> Result<()> {
        for vm in self.list(VmServiceListRequest::default()).await?.machines {
            let _ = self
                .free(VmServiceFreeRequest { vm_id: vm.id, cell_name: None })
                .await?;
        }
        Ok(())
    }
}

/// Validate the optional `cell_name` field on every VmService request.
/// `None`/empty string → `None` (local execution). Non-empty → validated
/// `CellName`. Invalid syntax → `Err`.
fn validated_cell_name(
    raw: &Option<String>,
) -> std::result::Result<Option<CellName>, VmServiceError> {
    match raw.as_deref() {
        None | Some("") => Ok(None),
        Some(_) => CellName::validate(raw.clone(), "cell_name", None)
            .map(Some)
            .map_err(|source| VmServiceError::InvalidCellName { source }),
    }
}

#[tonic::async_trait]
impl vm_service_server::VmService for VmService {
    async fn allocate(
        &self,
        request: Request<VmServiceAllocateRequest>,
    ) -> std::result::Result<Response<VmServiceAllocateResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.allocate(req).await?))
    }

    async fn free(
        &self,
        request: Request<VmServiceFreeRequest>,
    ) -> std::result::Result<Response<VmServiceFreeResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.free(req).await?))
    }

    async fn start(
        &self,
        request: Request<VmServiceStartRequest>,
    ) -> std::result::Result<Response<VmServiceStartResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.start(req).await?))
    }

    async fn stop(
        &self,
        request: Request<VmServiceStopRequest>,
    ) -> std::result::Result<Response<VmServiceStopResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.stop(req).await?))
    }

    async fn list(
        &self,
        request: Request<VmServiceListRequest>,
    ) -> std::result::Result<Response<VmServiceListResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.list(req).await?))
    }
}
