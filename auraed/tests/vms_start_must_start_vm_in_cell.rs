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

//! Verifies that a `cell_name`-scoped VmService request is proxied into
//! the nested auraed running inside that cell rather than executed on the
//! host.
//!
//! Hosting VMs *inside* a cell is not supported yet: the nested auraed has
//! no `Network`/IPAM of its own (prefix delegation for nested allocation
//! isn't wired). So the observable, correct behavior today is that the
//! proxy reaches the cell and the nested auraed refuses with
//! `Code::Unimplemented`. This test pins that contract — it proves the
//! proxy plumbing works end-to-end while documenting the current limit.
//! When nested VM hosting lands, this test should flip to asserting the
//! VM is created inside the cell.
//!
//! Setup:
//! 1. Allocate a process cell (no network isolation needed; the nested
//!    auraed only needs a unix socket back to the host).
//! 2. Issue `VmService.Allocate(cell_name=Some(...))` against the host.
//! 3. Expect `Code::Unimplemented` — the request was proxied into the cell
//!    and refused there. A host-side failure would be `FailedPrecondition`
//!    (networking unavailable) and a bad cell name would be `NotFound`, so
//!    `Unimplemented` specifically proves the proxy hit the nested auraed.

use client::cells::cell_service::CellServiceClient;
use client::vms::vm_service::VmServiceClient;
use common::cells::CellServiceAllocateRequestBuilder;
use proto::cells::CellServiceFreeRequest;
use proto::vms::{RootDrive, VirtualMachine, VmServiceAllocateRequest};
use tonic::Code;

mod common;

#[test_helpers_macros::shared_runtime_test]
#[ignore]
async fn vm_allocate_in_cell_proxies_to_nested_auraed() {
    let client = common::auraed_client().await;

    // 1. Allocate a process cell. The nested auraed just needs to run; we
    //    don't care about netns isolation for proxy plumbing.
    let alloc = CellServiceClient::allocate(
        &client,
        CellServiceAllocateRequestBuilder::new().build(),
    )
    .await
    .expect("failed to allocate cell");
    let cell_name = alloc.into_inner().cell_name;

    // 2. Allocate a VM through the proxy. The host daemon forwards the
    //    request to the cell's nested auraed.
    let vm_id = format!("ae-test-vm-{}", uuid::Uuid::new_v4());
    let result = VmServiceClient::allocate(
        &client,
        VmServiceAllocateRequest {
            machine: Some(VirtualMachine {
                id: vm_id.clone(),
                mem_size_mb: 256,
                vcpu_count: 1,
                kernel_img_path: "/var/lib/aurae/vm/kernel/vmlinux.bin"
                    .to_string(),
                kernel_args: vec![
                    "console=hvc0".to_string(),
                    "root=/dev/vda1".to_string(),
                ],
                root_drive: Some(RootDrive {
                    image_path: "/var/lib/aurae/vm/image/disk.raw".into(),
                    read_only: true,
                }),
                drive_mounts: vec![],
                auraed_address: String::new(),
            }),
            cell_name: Some(cell_name.clone()),
        },
    )
    .await;

    // 3. The nested auraed refuses: VMs can't be hosted inside a cell yet.
    //    `Unimplemented` (not `FailedPrecondition`/`NotFound`) is what
    //    proves the request was proxied into the cell.
    let status = result.expect_err("proxied allocate should be refused");
    assert_eq!(
        status.code(),
        Code::Unimplemented,
        "expected Unimplemented from the nested auraed, got: {status:?}"
    );

    // Cleanup: free the cell.
    let _ =
        CellServiceClient::free(&client, CellServiceFreeRequest { cell_name })
            .await;
}
