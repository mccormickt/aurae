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
use client::VM_CONTROL_TOKEN_HEADER;
use client::vms::vm_service::VmServiceClient;
use proto::vms::{
    VirtualMachineSummary, VmServiceAllocateRequest, VmServiceAllocateResponse,
    VmServiceFreeRequest, VmServiceFreeResponse, VmServiceListRequest,
    VmServiceListResponse, VmServiceStartRequest, VmServiceStartResponse,
    VmServiceStopRequest, VmServiceStopResponse, vm_service_server,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use validation::ValidatedField;

use crate::cells::cell_service::cells::{CellName, Cells};
use crate::init::Context;
use crate::init::network::Network;

use super::{
    VmControlToken,
    error::{Result, VmServiceError},
    proxy::proxy_to_cell,
    virtual_machine::{MountSpec, VmID, VmSpec},
    virtual_machines::VirtualMachines,
};

#[derive(Debug, Clone)]
enum VmServiceAccess {
    /// The daemon's externally authenticated server owns this service.
    Host,
    /// A nested auraed accepts only the capability inherited from its host.
    Cell(VmControlToken),
    /// Other contexts and manually started nested daemons fail closed.
    Disabled,
}

/// VmService struct manages the lifecycle of virtual machines.
#[derive(Debug, Clone)]
pub struct VmService {
    vms: Arc<Mutex<VirtualMachines>>,
    /// `None` if this auraed cannot host VMs: a non-daemon context, a cell
    /// without a delegated prefix, or a failed host network setup. Then
    /// each local Allocate and Start is refused.
    network: Option<Network>,
    /// Shared with `CellService`. A `cell_name`-scoped request is proxied
    /// to the nested auraed of that cell.
    cells: Arc<Mutex<Cells>>,
    access: VmServiceAccess,
    artifact_root: PathBuf,
    // TODO: ObserveService
}

impl VmService {
    /// Allocates a new instance of VmService. `control_token` is the
    /// capability that a nested auraed inherited from its host; it is
    /// ignored in the daemon context.
    pub fn new(
        network: Option<Network>,
        cells: Arc<Mutex<Cells>>,
        context: Context,
        control_token: Option<VmControlToken>,
        artifact_root: PathBuf,
    ) -> Self {
        let access = match (context, control_token) {
            (Context::Daemon, _) => VmServiceAccess::Host,
            (Context::Cell, Some(token)) => VmServiceAccess::Cell(token),
            _ => VmServiceAccess::Disabled,
        };
        Self {
            vms: Arc::new(Mutex::new(VirtualMachines::new(network.clone()))),
            network,
            cells,
            access,
            artifact_root,
        }
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<()> {
        match &self.access {
            VmServiceAccess::Host => Ok(()),
            VmServiceAccess::Cell(expected)
                if request
                    .metadata()
                    .get(VM_CONTROL_TOKEN_HEADER)
                    .and_then(|value| value.to_str().ok())
                    == Some(expected.expose_secret()) =>
            {
                Ok(())
            }
            VmServiceAccess::Cell(_) | VmServiceAccess::Disabled => {
                Err(VmServiceError::Unauthorized)
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn allocate(
        &self,
        request: VmServiceAllocateRequest,
    ) -> Result<VmServiceAllocateResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let request =
                VmServiceAllocateRequest { cell_name: None, ..request };
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                request,
                async |client, request| client.allocate(request).await,
            )
            .await;
        }

        if self.network.is_none() {
            return Err(VmServiceError::NetworkingUnavailable);
        }

        let Some(vm) = request.machine else {
            return Err(VmServiceError::MissingMachineConfig {});
        };

        let id = VmID::new(vm.id);
        let Some(root_drive) = vm.root_drive else {
            return Err(VmServiceError::MissingRootDrive { id: id.clone() });
        };

        let mut mounts = vec![MountSpec {
            host_path: validate_artifact_path(
                &self.artifact_root,
                &root_drive.image_path,
            )?,
            read_only: root_drive.read_only,
        }];
        mounts.extend(
            vm.drive_mounts
                .into_iter()
                .map(|mount| {
                    Ok(MountSpec {
                        host_path: validate_artifact_path(
                            &self.artifact_root,
                            &mount.image_path,
                        )?,
                        read_only: mount.read_only,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let spec = VmSpec {
            memory_size: vm.mem_size_mb,
            vcpu_count: vm.vcpu_count,
            kernel_image_path: validate_artifact_path(
                &self.artifact_root,
                &vm.kernel_img_path,
            )?,
            kernel_args: vm.kernel_args,
            mounts,
            net: vec![],
        };

        let mut vms = self.vms.lock().await;
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
            let request = VmServiceFreeRequest { cell_name: None, ..request };
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                request,
                async |client, request| client.free(request).await,
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
            let request = VmServiceStartRequest { cell_name: None, ..request };
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                request,
                async |client, request| client.start(request).await,
            )
            .await;
        }

        if self.network.is_none() {
            return Err(VmServiceError::NetworkingUnavailable);
        }
        let id = VmID::new(request.vm_id);
        let mut vms = self.vms.lock().await;
        let auraed_address = vms.start(&id).await.map_err(|e| {
            VmServiceError::FailedToStartError { id, source: e }
        })?;

        Ok(VmServiceStartResponse { auraed_address })
    }

    #[tracing::instrument(skip(self))]
    async fn stop(
        &self,
        request: VmServiceStopRequest,
    ) -> Result<VmServiceStopResponse> {
        if let Some(cell_name) = validated_cell_name(&request.cell_name)? {
            let request = VmServiceStopRequest { cell_name: None, ..request };
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                request,
                async |client, request| client.stop(request).await,
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
            let request = VmServiceListRequest { cell_name: None };
            return proxy_to_cell(
                &self.cells,
                &cell_name,
                request,
                async |client, request| client.list(request).await,
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
                        .auraed_address()
                        .map(|a| a.to_string())
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

/// Resolve a VM artifact to a regular file below the daemon-owned VM root.
/// Passing the canonical path to Cloud Hypervisor avoids a later symlink
/// traversal after this validation.
fn validate_artifact_path(root: &Path, requested: &str) -> Result<PathBuf> {
    let invalid = |source| VmServiceError::InvalidArtifactPath {
        path: requested.to_string(),
        source,
    };
    let root = fs::canonicalize(root).map_err(|e| {
        invalid(anyhow!("artifact root {}: {e}", root.display()))
    })?;
    let path = fs::canonicalize(requested)
        .map_err(|e| invalid(anyhow!("could not resolve path: {e}")))?;
    if !path.starts_with(&root) {
        return Err(invalid(anyhow!(
            "resolved path escapes {}",
            root.display()
        )));
    }
    let metadata = fs::metadata(&path)
        .map_err(|e| invalid(anyhow!("could not inspect path: {e}")))?;
    if !metadata.file_type().is_file() {
        return Err(invalid(anyhow!("path is not a regular file")));
    }
    Ok(path)
}

#[tonic::async_trait]
impl vm_service_server::VmService for VmService {
    async fn allocate(
        &self,
        request: Request<VmServiceAllocateRequest>,
    ) -> std::result::Result<Response<VmServiceAllocateResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();
        Ok(Response::new(self.allocate(req).await?))
    }

    async fn free(
        &self,
        request: Request<VmServiceFreeRequest>,
    ) -> std::result::Result<Response<VmServiceFreeResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();
        Ok(Response::new(self.free(req).await?))
    }

    async fn start(
        &self,
        request: Request<VmServiceStartRequest>,
    ) -> std::result::Result<Response<VmServiceStartResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();
        Ok(Response::new(self.start(req).await?))
    }

    async fn stop(
        &self,
        request: Request<VmServiceStopRequest>,
    ) -> std::result::Result<Response<VmServiceStopResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();
        Ok(Response::new(self.stop(req).await?))
    }

    async fn list(
        &self,
        request: Request<VmServiceListRequest>,
    ) -> std::result::Result<Response<VmServiceListResponse>, Status> {
        self.authorize(&request)?;
        let req = request.into_inner();
        Ok(Response::new(self.list(req).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn nested_vm_service_requires_matching_control_capability() {
        let token = VmControlToken::from_secret("secret".into());
        let service = VmService::new(
            None,
            Arc::new(Mutex::new(Cells::new_root(None))),
            Context::Cell,
            Some(token.clone()),
            "/var/lib/aurae/vm".into(),
        );

        let missing = Request::new(());
        assert!(service.authorize(&missing).is_err());

        let mut wrong = Request::new(());
        let _ = wrong.metadata_mut().insert(
            VM_CONTROL_TOKEN_HEADER,
            "wrong".parse().expect("metadata token"),
        );
        assert!(service.authorize(&wrong).is_err());

        let mut matching = Request::new(());
        let _ = matching.metadata_mut().insert(
            VM_CONTROL_TOKEN_HEADER,
            token.expose_secret().parse().expect("metadata token"),
        );
        assert!(service.authorize(&matching).is_ok());
    }

    /// A nested auraed without an inherited capability fails closed, also
    /// for a request that carries a token. The host daemon needs no token.
    #[test]
    fn access_without_capability_is_disabled_and_host_is_open() {
        let cells = Arc::new(Mutex::new(Cells::new_root(None)));
        let mut request = Request::new(());
        let _ = request.metadata_mut().insert(
            VM_CONTROL_TOKEN_HEADER,
            "any".parse().expect("metadata token"),
        );

        let disabled = VmService::new(
            None,
            cells.clone(),
            Context::Cell,
            None,
            "/var/lib/aurae/vm".into(),
        );
        assert!(matches!(
            disabled.authorize(&request),
            Err(VmServiceError::Unauthorized)
        ));

        let host = VmService::new(
            None,
            cells,
            Context::Daemon,
            None,
            "/var/lib/aurae/vm".into(),
        );
        assert!(host.authorize(&Request::new(())).is_ok());
    }

    #[test]
    fn artifact_path_must_resolve_to_regular_file_below_vm_root() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp.path().join("vm");
        fs::create_dir(&root).expect("VM root");
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").expect("kernel image");
        assert_eq!(
            validate_artifact_path(&root, kernel.to_str().expect("UTF-8 path"))
                .expect("allowed artifact"),
            kernel
        );

        let outside = temp.path().join("outside");
        fs::write(&outside, b"host file").expect("outside file");
        let escape = root.join("escape");
        symlink(&outside, &escape).expect("escape symlink");
        assert!(
            validate_artifact_path(&root, escape.to_str().expect("UTF-8 path"))
                .is_err()
        );
        assert!(
            validate_artifact_path(&root, root.to_str().expect("UTF-8 path"))
                .is_err()
        );
    }
}
