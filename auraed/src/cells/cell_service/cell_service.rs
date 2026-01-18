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

use super::{
    Result,
    cells::{CellName, Cells, CellsCache},
    error::CellsServiceError,
    executables::Executables,
    validation::{
        ValidatedCellServiceAllocateRequest, ValidatedCellServiceFreeRequest,
        ValidatedCellServiceStartRequest, ValidatedCellServiceStopRequest,
    },
};
use crate::{
    cells::cell_service::cells::CellsError, observe::ObserveService,
    vms::VmService,
};
use ::validation::{ValidatedField, ValidatedType};
use backoff::backoff::Backoff;
use client::{
    AuraeSocket, CertMaterial, Client, ClientError,
    cells::cell_service::CellServiceClient,
};
use proto::{
    cells::{
        Cell, CellGraphNode, CellServiceAllocateRequest,
        CellServiceAllocateResponse, CellServiceFreeRequest,
        CellServiceFreeResponse, CellServiceListRequest,
        CellServiceListResponse, CellServiceStartRequest,
        CellServiceStartResponse, CellServiceStopRequest,
        CellServiceStopResponse, CpuController, CpusetController,
        MemoryController, cell_service_server,
    },
    common::ExecutionTarget,
    observe::LogChannelType,
};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use std::{process::ExitStatus, sync::Arc};
use tokio::sync::Mutex;
use tonic::{Code, Request, Response, Status};
use tracing::{info, instrument, trace, warn};

/**
 * Macro to perform an operation within a cell.
 * It retries the operation with an exponential backoff strategy in case of connection errors.
 */
macro_rules! do_in_cell {
     ($self:ident, $cell_name:ident, $function:ident, $request:ident) => {{
         // Retrieve the client socket for the specified cell
         let client_socket = {
             let mut cells = $self.cells.lock().await;
             cells
             .get(&$cell_name, |cell| cell.client_socket())
             .map_err(CellsServiceError::CellsError)?
         };

         // Initialize the exponential backoff strategy for retrying the operation
         let mut retry_strategy = backoff::ExponentialBackoffBuilder::new()
             .with_initial_interval(Duration::from_millis(50)) // 1st retry in 50ms
             .with_multiplier(10.0) // 10x the delay each attempt
             .with_randomization_factor(0.5) // with a randomness of +/-50%
             .with_max_interval(Duration::from_secs(3)) // but never delay more than 3s
             .with_max_elapsed_time(Some(Duration::from_secs(20))) // or 20s total
             .build();

         // Attempt to create a new client with retries in case of connection errors
         let client = loop {
             match Client::new_no_tls(client_socket.clone()).await {
                 Ok(client) => break Ok(client),
                 e @ Err(ClientError::ConnectionError(_)) => {
                     trace!("aurae client failed to connect: {e:?}");
                     if let Some(delay) = retry_strategy.next_backoff() {
                         trace!("retrying in {delay:?}");
                         tokio::time::sleep(delay).await
                     } else {
                         break e
                     }
                 }
                 e => break e
             }
         }.map_err(CellsServiceError::from)?;

         // Attempt the operation with the backoff strategy
         backoff::future::retry(
             retry_strategy,
             || async {
                 match client.$function($request.clone()).await {
                     Ok(res) => Ok(res),
                     Err(e) if e.code() == Code::Unknown && e.message() == "transport error" => {
                         Err(e)?;
                         unreachable!();
                     }
                     Err(e) => Err(backoff::Error::Permanent(e))
                 }
             },
         )
         .await
     }};
 }

/// Result of resolving an execution target.
#[derive(Debug)]
pub enum ResolvedTarget {
    /// Target is local - execute directly without forwarding.
    Local,
    /// Target is a cell - forward via Unix socket (no TLS).
    Cell { socket: AuraeSocket },
    /// Target is a VM - forward via network socket with TLS.
    Vm { socket: AuraeSocket, cell_path: Option<String> },
}

/// Macro to perform an operation within a target (VM or cell).
/// It resolves the target, creates the appropriate client, and retries
/// the operation with an exponential backoff strategy in case of connection errors.
macro_rules! do_in_target {
    ($self:ident, $target:expr, $function:ident, $request:ident, $transform_request:expr) => {{
        let resolved = $self.resolve_target($target).await?;

        match resolved {
            ResolvedTarget::Local => {
                // This shouldn't happen - caller should check for local target
                Err(CellsServiceError::Other(
                    "do_in_target! called with local target".into(),
                )
                .into())
            }
            ResolvedTarget::Cell { socket } => {
                // Cell forwarding uses Unix sockets (no TLS)
                let mut retry_strategy =
                    backoff::ExponentialBackoffBuilder::new()
                        .with_initial_interval(Duration::from_millis(50))
                        .with_multiplier(10.0)
                        .with_randomization_factor(0.5)
                        .with_max_interval(Duration::from_secs(3))
                        .with_max_elapsed_time(Some(Duration::from_secs(20)))
                        .build();

                let client = loop {
                    match Client::new_no_tls(socket.clone()).await {
                        Ok(client) => break Ok(client),
                        e @ Err(ClientError::ConnectionError(_)) => {
                            trace!("aurae client failed to connect: {e:?}");
                            if let Some(delay) = retry_strategy.next_backoff() {
                                trace!("retrying in {delay:?}");
                                tokio::time::sleep(delay).await
                            } else {
                                break e;
                            }
                        }
                        e => break e,
                    }
                }
                .map_err(CellsServiceError::from)?;

                let transformed_request = $transform_request($request, None);
                backoff::future::retry(retry_strategy, || async {
                    match client.$function(transformed_request.clone()).await {
                        Ok(res) => Ok(res),
                        Err(e)
                            if e.code() == Code::Unknown
                                && e.message() == "transport error" =>
                        {
                            Err(e)?;
                            unreachable!();
                        }
                        Err(e) => Err(backoff::Error::Permanent(e)),
                    }
                })
                .await
            }
            ResolvedTarget::Vm { socket, cell_path } => {
                // VM target - use TLS for network socket
                let cert_material = $self.load_cert_material().await?;

                let mut retry_strategy =
                    backoff::ExponentialBackoffBuilder::new()
                        .with_initial_interval(Duration::from_millis(50))
                        .with_multiplier(10.0)
                        .with_randomization_factor(0.5)
                        .with_max_interval(Duration::from_secs(3))
                        .with_max_elapsed_time(Some(Duration::from_secs(20)))
                        .build();

                let client = loop {
                    match Client::new_with_tls(socket.clone(), &cert_material)
                        .await
                    {
                        Ok(client) => break Ok(client),
                        e @ Err(ClientError::ConnectionError(_)) => {
                            trace!(
                                "aurae client failed to connect to VM: {e:?}"
                            );
                            if let Some(delay) = retry_strategy.next_backoff() {
                                trace!("retrying in {delay:?}");
                                tokio::time::sleep(delay).await
                            } else {
                                break e;
                            }
                        }
                        e => break e,
                    }
                }
                .map_err(CellsServiceError::from)?;

                // Transform request: strip vm_id, keep cell_path as cell_name
                let transformed_request =
                    $transform_request($request, cell_path);
                backoff::future::retry(retry_strategy, || async {
                    match client.$function(transformed_request.clone()).await {
                        Ok(res) => Ok(res),
                        Err(e)
                            if e.code() == Code::Unknown
                                && e.message() == "transport error" =>
                        {
                            Err(e)?;
                            unreachable!();
                        }
                        Err(e) => Err(backoff::Error::Permanent(e)),
                    }
                })
                .await
            }
        }
    }};
}

/// CellService struct manages the lifecycle of cells and executables.
#[derive(Debug, Clone)]
pub struct CellService {
    cells: Arc<Mutex<Cells>>,
    executables: Arc<Mutex<Executables>>,
    observe_service: ObserveService,
    /// Reference to VmService for looking up VM socket addresses.
    /// Used to forward requests to auraed instances running inside VMs.
    vm_service: Option<VmService>,
}

impl CellService {
    /// Creates a new instance of CellService.
    ///
    /// # Arguments
    /// * `observe_service` - An instance of ObserveService to manage log channels.
    pub fn new(observe_service: ObserveService) -> Self {
        CellService {
            cells: Default::default(),
            executables: Default::default(),
            observe_service,
            vm_service: None,
        }
    }

    /// Creates a new instance of CellService with VmService for VM target support.
    ///
    /// # Arguments
    /// * `observe_service` - An instance of ObserveService to manage log channels.
    /// * `vm_service` - An instance of VmService for looking up VM socket addresses.
    pub fn new_with_vm_service(
        observe_service: ObserveService,
        vm_service: VmService,
    ) -> Self {
        CellService {
            cells: Default::default(),
            executables: Default::default(),
            observe_service,
            vm_service: Some(vm_service),
        }
    }

    /// Resolves an execution target to determine where and how to forward a request.
    ///
    /// # Arguments
    /// * `target` - The execution target to resolve.
    ///
    /// # Returns
    /// A `ResolvedTarget` indicating how to handle the request.
    async fn resolve_target(
        &self,
        target: &ExecutionTarget,
    ) -> Result<ResolvedTarget> {
        // Check if VM target is specified
        if let Some(vm_id) = &target.vm_id {
            let vm_service = self.vm_service.as_ref().ok_or_else(|| {
                CellsServiceError::Other(
                    "VM targeting not available (VmService not configured)"
                        .into(),
                )
            })?;

            // Look up the VM's socket address
            let socket_addr =
                vm_service.get_vm_socket(vm_id).await.ok_or_else(|| {
                    CellsServiceError::VmNotRunning { vm_id: vm_id.clone() }
                })?;

            return Ok(ResolvedTarget::Vm {
                socket: AuraeSocket::Addr(socket_addr),
                cell_path: target.cell_path.clone(),
            });
        }

        // Check if cell path is specified
        if let Some(cell_path) = &target.cell_path {
            let cell_name =
                CellName::validate(Some(cell_path.clone()), "cell_path", None)
                    .map_err(|e| {
                        CellsServiceError::Other(format!(
                            "Invalid cell path: {}",
                            e
                        ))
                    })?;
            let mut cells = self.cells.lock().await;

            // Retrieve the client socket for the specified cell
            let client_socket = cells
                .get(&cell_name, |cell| cell.client_socket())
                .map_err(CellsServiceError::CellsError)?;

            return Ok(ResolvedTarget::Cell { socket: client_socket });
        }

        // Neither VM nor cell specified - local execution
        Ok(ResolvedTarget::Local)
    }

    /// Loads certificate material for TLS connections to VMs.
    ///
    /// This uses the default certificate paths from /etc/aurae/pki/.
    async fn load_cert_material(&self) -> Result<CertMaterial> {
        use client::AuthConfig;

        // Use default paths - same as the auraed runtime
        let auth_config = AuthConfig {
            ca_crt: "/etc/aurae/pki/ca.crt".to_string(),
            client_crt: "/etc/aurae/pki/_signed.client.nova.crt".to_string(),
            client_key: "/etc/aurae/pki/client.nova.key".to_string(),
        };

        auth_config.to_cert_material().await.map_err(|e| {
            CellsServiceError::Other(format!(
                "Failed to load certificate material: {}",
                e
            ))
        })
    }

    /// Allocates a new cell based on the provided request.
    ///
    /// # Arguments
    /// * `request` - A validated request to allocate a cell.
    ///
    /// # Returns
    /// A result containing the CellServiceAllocateResponse or an error.
    /// Frees an existing cell based on the provided request.
    #[tracing::instrument(skip(self))]
    async fn allocate(
        &self,
        request: ValidatedCellServiceAllocateRequest,
    ) -> Result<CellServiceAllocateResponse> {
        // Initialize the cell
        let ValidatedCellServiceAllocateRequest { cell, .. } = request;

        let cell_name = cell.name.clone();
        let cell_spec = cell.into();

        let mut cells = self.cells.lock().await;

        let cell = cells.allocate(cell_name, cell_spec)?;

        Ok(CellServiceAllocateResponse {
            cell_name: cell.name().clone().to_string(),
            cgroup_v2: cell.v2().expect("allocated cell returns `Some`"),
        })
    }

    /// Frees a cell.
    ///
    /// # Arguments
    /// * `request` - A request containing CellServiceFreeRequest.
    ///
    /// # Returns
    /// A response containing CellServiceFreeResponse or a Status error.
    #[tracing::instrument(skip(self))]
    async fn free(
        &self,
        request: ValidatedCellServiceFreeRequest,
    ) -> Result<CellServiceFreeResponse> {
        let ValidatedCellServiceFreeRequest { cell_name, .. } = request;

        info!("CellService: free() cell_name={cell_name:?}");

        let mut cells = self.cells.lock().await;

        cells.free(&cell_name)?;

        Ok(CellServiceFreeResponse::default())
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn free_all(&self) -> Result<()> {
        let mut cells = self.cells.lock().await;

        // Attempt to gracefully free all cells
        cells.broadcast_free();

        // The cells that remain failed to shut down for some reason.
        // Forcefully kill any remaining cells that failed to shut down
        cells.broadcast_kill();

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    /// Handles a start request.
    ///
    /// # Arguments
    /// * `request` - A request containing CellServiceStartRequest.
    ///
    /// # Returns
    /// A response containing CellServiceStartResponse or a Status error.
    async fn start(
        &self,
        request: ValidatedCellServiceStartRequest,
    ) -> std::result::Result<Response<CellServiceStartResponse>, Status> {
        let ValidatedCellServiceStartRequest {
            cell_name,
            executable,
            uid,
            gid,
            ..
        } = request;

        assert!(cell_name.is_none());
        info!("CellService: start() executable={:?}", executable);

        let mut executables = self.executables.lock().await;

        // Start the executable and handle any errors
        let executable = executables
            .start(executable, uid, gid)
            .map_err(CellsServiceError::ExecutablesError)?;

        // Retrieve the process ID (PID) of the started executable
        let pid = executable
            .pid()
            .map_err(CellsServiceError::Io)?
            .expect("pid")
            .as_raw();

        // Register the stdout log channel for the executable's PID
        if let Err(e) = self
            .observe_service
            .register_sub_process_channel(
                pid,
                LogChannelType::Stdout,
                executable.stdout.clone(),
            )
            .await
        {
            warn!("failed to register stdout channel for pid {pid}: {e}");
        }

        // Register the stderr log channel for the executable's PID
        if let Err(e) = self
            .observe_service
            .register_sub_process_channel(
                pid,
                LogChannelType::Stderr,
                executable.stderr.clone(),
            )
            .await
        {
            warn!("failed to register stderr channel for pid {pid}: {e}");
        }

        let (self_uid, self_gid) =
            std::fs::metadata("/proc/self").map(|m| (m.uid(), m.gid()))?;

        Ok(Response::new(CellServiceStartResponse {
            pid,
            uid: uid.unwrap_or(self_uid),
            gid: gid.unwrap_or(self_gid),
        }))
    }

    #[tracing::instrument(skip(self))]
    /// Handles the stop request.
    ///
    /// # Arguments
    /// * `request` - A request containing CellServiceStopRequest.
    ///
    /// # Returns
    /// A response containing CellServiceStopResponse or a Status error.
    async fn stop(
        &self,
        request: ValidatedCellServiceStopRequest,
    ) -> std::result::Result<Response<CellServiceStopResponse>, Status> {
        let ValidatedCellServiceStopRequest {
            cell_name, executable_name, ..
        } = request;

        assert!(cell_name.is_none());
        info!("CellService: stop() executable_name={:?}", executable_name,);

        let pid = {
            let mut executables = self.executables.lock().await;

            // Retrieve the process ID (PID) of the executable to be stopped
            let pid = executables
                .get(&executable_name)
                .map_err(CellsServiceError::ExecutablesError)?
                .pid()
                .map_err(CellsServiceError::Io)?
                .expect("pid")
                .as_raw();

            // Stop the executable and handle any errors
            let _: ExitStatus = executables
                .stop(&executable_name)
                .await
                .map_err(CellsServiceError::ExecutablesError)?;

            pid
        };

        // Remove the executable's logs from the observe service.
        if let Err(e) = self
            .observe_service
            .unregister_sub_process_channel(pid, LogChannelType::Stdout)
            .await
        {
            warn!("failed to unregister stdout channel for pid {pid}: {e}");
        }
        if let Err(e) = self
            .observe_service
            .unregister_sub_process_channel(pid, LogChannelType::Stderr)
            .await
        {
            warn!("failed to unregister stderr channel for pid {pid}: {e}");
        }

        Ok(Response::new(CellServiceStopResponse::default()))
    }

    /// Starts an executable in a target (VM or cell) using the unified targeting mechanism.
    #[tracing::instrument(skip(self))]
    async fn start_in_target(
        &self,
        target: &ExecutionTarget,
        request: CellServiceStartRequest,
    ) -> std::result::Result<Response<CellServiceStartResponse>, Status> {
        // Transform function for the request - strips vm_id, sets cell_name from cell_path
        let transform_request = |req: CellServiceStartRequest,
                                 cell_path: Option<String>|
         -> CellServiceStartRequest {
            CellServiceStartRequest {
                cell_name: cell_path,
                executable: req.executable,
                uid: req.uid,
                gid: req.gid,
                execution_target: None, // Clear execution_target for forwarded request
            }
        };

        do_in_target!(self, target, start, request, transform_request)
    }

    /// Stops an executable in a target (VM or cell) using the unified targeting mechanism.
    #[tracing::instrument(skip(self))]
    async fn stop_in_target(
        &self,
        target: &ExecutionTarget,
        request: CellServiceStopRequest,
    ) -> std::result::Result<Response<CellServiceStopResponse>, Status> {
        // Transform function for the request - strips vm_id, sets cell_name from cell_path
        let transform_request = |req: CellServiceStopRequest,
                                 cell_path: Option<String>|
         -> CellServiceStopRequest {
            CellServiceStopRequest {
                cell_name: cell_path,
                executable_name: req.executable_name,
                execution_target: None, // Clear execution_target for forwarded request
            }
        };

        do_in_target!(self, target, stop, request, transform_request)
    }

    /// Allocates a cell in a target (VM or cell) using the unified targeting mechanism.
    #[tracing::instrument(skip(self))]
    async fn allocate_in_target(
        &self,
        target: &ExecutionTarget,
        request: CellServiceAllocateRequest,
    ) -> std::result::Result<Response<CellServiceAllocateResponse>, Status>
    {
        // Transform function for the request - strips vm_id, clears parent_target
        // The cell_path becomes the context where the cell is created
        let transform_request = |req: CellServiceAllocateRequest,
                                 _cell_path: Option<String>|
         -> CellServiceAllocateRequest {
            CellServiceAllocateRequest {
                cell: req.cell,
                parent_target: None, // Clear parent_target for forwarded request
            }
        };

        do_in_target!(self, target, allocate, request, transform_request)
    }

    /// Frees a cell in a target (VM or cell) using the unified targeting mechanism.
    #[tracing::instrument(skip(self))]
    async fn free_in_target(
        &self,
        target: &ExecutionTarget,
        request: CellServiceFreeRequest,
    ) -> std::result::Result<Response<CellServiceFreeResponse>, Status> {
        // Transform function for the request - strips vm_id, clears parent_target
        let transform_request = |req: CellServiceFreeRequest,
                                 _cell_path: Option<String>|
         -> CellServiceFreeRequest {
            CellServiceFreeRequest {
                cell_name: req.cell_name,
                parent_target: None, // Clear parent_target for forwarded request
            }
        };

        do_in_target!(self, target, free, request, transform_request)
    }

    /// Lists cells in a target (VM or cell) using the unified targeting mechanism.
    #[tracing::instrument(skip(self))]
    async fn list_in_target(
        &self,
        target: &ExecutionTarget,
        request: CellServiceListRequest,
    ) -> std::result::Result<Response<CellServiceListResponse>, Status> {
        // Transform function for the request - clears execution_target for forwarded request
        let transform_request = |_req: CellServiceListRequest,
                                 _cell_path: Option<String>|
         -> CellServiceListRequest {
            CellServiceListRequest {
                execution_target: None, // Clear execution_target for forwarded request
            }
        };

        do_in_target!(self, target, list, request, transform_request)
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn stop_all(&self) -> Result<()> {
        let mut executables = self.executables.lock().await;
        // Broadcast a stop signal to all executables
        executables.broadcast_stop().await;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn list(&self) -> Result<CellServiceListResponse> {
        let cells = self.cells.lock().await;

        // Retrieve all cells and convert them for returning
        let cells = cells
            .get_all(|x| x.try_into())
            .expect("cells doesn't error")
            .into_iter()
            .filter_map(|x| x.ok())
            .collect();

        Ok(CellServiceListResponse { cells })
    }
}

impl TryFrom<&super::cells::Cell> for CellGraphNode {
    type Error = CellsError;

    /// Converts a Cell into a CellGraphNode.
    ///
    /// # Arguments
    /// * `value` - A reference to the Cell.
    ///
    /// # Returns
    /// A result containing the CellGraphNode or an error.
    fn try_from(
        value: &super::cells::Cell,
    ) -> std::result::Result<Self, Self::Error> {
        // Extract the name and specification of the cell
        let name = value.name();
        let spec = value.spec();
        // Retrieve and convert all child cells
        let children = CellsCache::get_all(value, |x| x.try_into())?
            .into_iter()
            .filter_map(|x| x.ok())
            .collect();

        // Extract cgroup and isolation specifications
        let super::cells::CellSpec { cgroup_spec, iso_ctl } = spec;
        // Extract CPU, cpuset, and memory specifications
        let super::cells::cgroups::CgroupSpec { cpu, cpuset, memory } =
            cgroup_spec;

        Ok(Self {
            // Create a new Cell instance with the extracted specifications
            cell: Some(Cell {
                name: name.to_string(),
                cpu: cpu.as_ref().map(|x| x.into()),
                cpuset: cpuset.as_ref().map(|x| x.into()),
                memory: memory.as_ref().map(|x| x.into()),
                isolate_process: iso_ctl.isolate_process,
                isolate_network: iso_ctl.isolate_network,
            }),
            children,
        })
    }
}

impl From<&super::cells::cgroups::CpuController> for CpuController {
    fn from(value: &super::cells::cgroups::CpuController) -> Self {
        let super::cells::cgroups::CpuController { weight, max, period } =
            value.clone();

        Self {
            weight: weight.map(|x| x.into_inner()),
            max: max.map(|x| x.into_inner()),
            period,
        }
    }
}

impl From<&super::cells::cgroups::cpuset::CpusetController>
    for CpusetController
{
    fn from(value: &super::cells::cgroups::CpusetController) -> Self {
        let super::cells::cgroups::CpusetController { cpus, mems } =
            value.clone();

        Self {
            cpus: cpus.map(|x| x.into_inner()),
            mems: mems.map(|x| x.into_inner()),
        }
    }
}

impl From<&super::cells::cgroups::memory::MemoryController>
    for MemoryController
{
    fn from(value: &super::cells::cgroups::MemoryController) -> Self {
        let super::cells::cgroups::MemoryController { min, low, high, max } =
            value.clone();

        Self {
            min: min.map(|x| x.into_inner()),
            low: low.map(|x| x.into_inner()),
            high: high.map(|x| x.into_inner()),
            max: max.map(|x| x.into_inner()),
        }
    }
}

/// ### Mapping cgroup options to the Cell API
///
/// Here we *only* expose options from the CgroupBuilder
/// as our features in Aurae need them! We do not try to
/// "map" everything as much as we start with a few small
/// features and add as needed.
///
// Example builder options can be found: https://github.com/kata-containers/cgroups-rs/blob/main/tests/builder.rs
// Cgroup documentation: https://man7.org/linux/man-pages/man7/cgroups.7.html
#[tonic::async_trait]
impl cell_service_server::CellService for CellService {
    async fn allocate(
        &self,
        request: Request<CellServiceAllocateRequest>,
    ) -> std::result::Result<Response<CellServiceAllocateResponse>, Status>
    {
        // Extract the inner request from the request
        let request = request.into_inner();

        // Check for parent_target for allocating cell in a VM or nested cell
        if let Some(ref target) = request.parent_target {
            if target.vm_id.is_some() || target.cell_path.is_some() {
                // Forward to VM or cell using the unified mechanism
                return self.allocate_in_target(&target.clone(), request).await;
            }
        }

        // Validate the allocate request
        let request = ValidatedCellServiceAllocateRequest::validate(
            request.clone(),
            None,
        )?;

        // return the allocated cell
        Ok(Response::new(self.allocate(request).await?))
    }

    #[instrument(skip(self))]
    async fn free(
        &self,
        request: Request<CellServiceFreeRequest>,
    ) -> std::result::Result<Response<CellServiceFreeResponse>, Status> {
        let request = request.into_inner();

        // Check for parent_target for freeing cell in a VM or nested cell
        if let Some(ref target) = request.parent_target {
            if target.vm_id.is_some() || target.cell_path.is_some() {
                // Forward to VM or cell using the unified mechanism
                return self.free_in_target(&target.clone(), request).await;
            }
        }

        // Validate the free request
        let request =
            ValidatedCellServiceFreeRequest::validate(request.clone(), None)?;

        // free the cell
        Ok(Response::new(self.free(request).await?))
    }

    #[instrument(skip(self))]
    async fn start(
        &self,
        request: Request<CellServiceStartRequest>,
    ) -> std::result::Result<Response<CellServiceStartResponse>, Status> {
        let mut request = request.into_inner();

        // Convert legacy cell_name to execution_target for unified handling
        let target = if let Some(ref target) = request.execution_target {
            if target.vm_id.is_some() || target.cell_path.is_some() {
                Some(target.clone())
            } else {
                None
            }
        } else if let Some(ref cell_name) = request.cell_name {
            // Convert legacy cell_name to ExecutionTarget
            Some(ExecutionTarget {
                vm_id: None,
                cell_path: Some(cell_name.clone()),
            })
        } else {
            None
        };

        // If we have a target, forward the request
        if let Some(target) = target {
            // Clear cell_name for forwarded request (it's now in the target)
            request.cell_name = None;
            return self.start_in_target(&target, request).await;
        }

        // Local execution
        let request =
            ValidatedCellServiceStartRequest::validate(request, None)?;
        Ok(self.start(request).await?)
    }

    #[instrument(skip(self))]
    async fn stop(
        &self,
        request: Request<CellServiceStopRequest>,
    ) -> std::result::Result<Response<CellServiceStopResponse>, Status> {
        let mut request = request.into_inner();

        // Convert legacy cell_name to execution_target for unified handling
        let target = if let Some(ref target) = request.execution_target {
            if target.vm_id.is_some() || target.cell_path.is_some() {
                Some(target.clone())
            } else {
                None
            }
        } else if let Some(ref cell_name) = request.cell_name {
            // Convert legacy cell_name to ExecutionTarget
            Some(ExecutionTarget {
                vm_id: None,
                cell_path: Some(cell_name.clone()),
            })
        } else {
            None
        };

        // If we have a target, forward the request
        if let Some(target) = target {
            // Clear cell_name for forwarded request (it's now in the target)
            request.cell_name = None;
            return self.stop_in_target(&target, request).await;
        }

        // Local execution
        let request = ValidatedCellServiceStopRequest::validate(request, None)?;
        Ok(self.stop(request).await?)
    }

    /// Response with a list of cells
    ///
    /// # Arguments
    /// * `request` - A request containing CellServiceListRequest.
    ///
    /// # Returns
    /// A response containing CellServiceListResponse or a Status error.
    async fn list(
        &self,
        request: Request<CellServiceListRequest>,
    ) -> std::result::Result<Response<CellServiceListResponse>, Status> {
        let request = request.into_inner();

        // Check if we need to forward this request to another target
        if let Some(ref target) = request.execution_target {
            // Clone the target before passing request
            let target = target.clone();
            // Forward to the target (VM or cell)
            return self.list_in_target(&target, request).await;
        }

        // Local execution
        Ok(Response::new(self.list().await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AURAED_RUNTIME, AuraedRuntime};
    use crate::{
        cells::cell_service::validation::{
            ValidatedCell, ValidatedCpuController, ValidatedCpusetController,
            ValidatedMemoryController,
        },
        logging::log_channel::LogChannel,
    };
    use iter_tools::Itertools;
    use proto::{
        cells::{CellServiceStartRequest, CellServiceStopRequest, Executable},
        observe::LogChannelType,
    };
    use std::os::unix::fs::MetadataExt;
    use test_helpers::*;

    /// Test for the list function.
    #[tokio::test]
    async fn test_list() {
        skip_if_not_root!("test_list");
        skip_if_seccomp!("test_list");

        // Set the Auraed runtime for the test
        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        // Create a new instance of CellService for testing
        let service = CellService::new(ObserveService::new(
            LogChannel::new(String::from("test")),
            (None, None, None),
        ));

        // Allocate a parent cell for testing
        let parent_cell_name = format!("ae-test-{}", uuid::Uuid::new_v4());
        assert!(
            service.allocate(allocate_request(&parent_cell_name)).await.is_ok()
        );

        // Allocate a nested cell within the parent cell for testing
        let nested_cell_name =
            format!("{}/ae-test-{}", &parent_cell_name, uuid::Uuid::new_v4());
        assert!(
            service.allocate(allocate_request(&nested_cell_name)).await.is_ok()
        );

        // Allocate a cell without children for testing
        let cell_without_children_name =
            format!("ae-test-{}", uuid::Uuid::new_v4());
        assert!(
            service
                .allocate(allocate_request(&cell_without_children_name))
                .await
                .is_ok()
        );

        // List all cells and verify the result
        let result = service.list().await;
        assert!(result.is_ok());

        let list = result.unwrap();
        assert_eq!(list.cells.len(), 2);

        // Verify the root cell names
        let mut expected_root_cell_names =
            vec![&parent_cell_name, &cell_without_children_name];
        expected_root_cell_names.sort();

        let mut actual_root_cell_names = list
            .cells
            .iter()
            .map(|c| c.cell.as_ref().unwrap().name.as_str())
            .collect_vec();
        actual_root_cell_names.sort();
        assert_eq!(actual_root_cell_names, expected_root_cell_names);

        // Verify the parent cell name in child cells.
        let parent_cell = list
            .cells
            .iter()
            .find(|p| p.cell.as_ref().unwrap().name.eq(&parent_cell_name));
        assert!(parent_cell.is_some());

        let expected_nested_cell_names = vec![&nested_cell_name];
        let actual_nested_cell_names = parent_cell
            .unwrap()
            .children
            .iter()
            .map(|c| c.cell.as_ref().unwrap().name.as_str())
            .collect_vec();
        assert_eq!(actual_nested_cell_names, expected_nested_cell_names);
    }

    /// Helper function to create a ValidatedCellServiceAllocateRequest.
    ///
    /// # Arguments
    /// * `cell_name` - The name of the cell.
    ///
    /// # Returns
    /// A ValidatedCellServiceAllocateRequest.
    fn allocate_request(
        cell_name: &str,
    ) -> ValidatedCellServiceAllocateRequest {
        // Create a validated cell for the allocate request
        let cell = ValidatedCell {
            name: CellName::from(cell_name),
            cpu: Some(ValidatedCpuController {
                weight: None,
                max: None,
                period: None,
            }),
            cpuset: Some(ValidatedCpusetController { cpus: None, mems: None }),
            memory: Some(ValidatedMemoryController {
                min: None,
                low: None,
                high: None,
                max: None,
            }),
            isolate_process: false,
            isolate_network: false,
        };
        // Return the validated allocate request
        ValidatedCellServiceAllocateRequest { cell, parent_target: None }
    }

    #[tokio::test]
    async fn start_registers_log_channels_and_returns_uid_gid() {
        let observe_service = ObserveService::new(
            LogChannel::new(String::from("test")),
            (None, None, None),
        );
        let service = CellService::new(observe_service.clone());

        let executable_name = format!("exec-{}", uuid::Uuid::new_v4().simple());

        let start_request = CellServiceStartRequest {
            cell_name: None,
            executable: Some(Executable {
                name: executable_name.clone(),
                command: "sleep 30".into(),
                description: "test executable".into(),
            }),
            uid: None,
            gid: None,
            execution_target: None,
        };

        let validated =
            ValidatedCellServiceStartRequest::validate(start_request, None)
                .expect("validated start request");

        let (expected_uid, expected_gid) = std::fs::metadata("/proc/self")
            .map(|m| (m.uid(), m.gid()))
            .expect("failed to read current process metadata for uid/gid");

        let response =
            service.start(validated).await.expect("start request failed");
        let response = response.into_inner();

        assert!(response.pid > 0, "expected pid to be recorded");
        assert_eq!(
            response.uid, expected_uid,
            "start should inherit current uid when unset"
        );
        assert_eq!(
            response.gid, expected_gid,
            "start should inherit current gid when unset"
        );

        assert!(
            observe_service
                .has_sub_process_channel(response.pid, LogChannelType::Stdout)
                .await,
            "stdout channel should be registered for pid {}",
            response.pid
        );
        assert!(
            observe_service
                .has_sub_process_channel(response.pid, LogChannelType::Stderr)
                .await,
            "stderr channel should be registered for pid {}",
            response.pid
        );

        let stop_request = CellServiceStopRequest {
            cell_name: None,
            executable_name: executable_name.clone(),
            execution_target: None,
        };
        let validated_stop =
            ValidatedCellServiceStopRequest::validate(stop_request, None)
                .expect("validated stop request");
        let _ =
            service.stop(validated_stop).await.expect("stop request failed");

        assert!(
            !observe_service
                .has_sub_process_channel(response.pid, LogChannelType::Stdout)
                .await,
            "stdout channel should be removed after stop"
        );
        assert!(
            !observe_service
                .has_sub_process_channel(response.pid, LogChannelType::Stderr)
                .await,
            "stderr channel should be removed after stop"
        );
    }
}
