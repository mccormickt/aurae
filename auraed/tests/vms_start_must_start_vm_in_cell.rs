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

//! Verifies that a `cell_name`-scoped VmService request is proxied into the
//! nested auraed inside an *isolated* cell, which hosts the VM out of the
//! prefix the host delegated to that cell — and that the VM's guest auraed
//! is reachable from the host through the full datapath:
//!
//!   host → netkit primary (routes the cell's /112) → cell netns → VM TAP →
//!   guest auraed
//!
//! This exercises every piece of the VM-in-cell architecture: the proxy, the
//! nested auraed's seeded `Network`/IPAM, in-cell forwarding, the routed TAP
//! endpoint, and the cell-net guard accepting the VM's source address (it
//! lies inside the cell's delegated /112, so anti-spoof passes).
//!
//! `#[ignore]`-gated and root/seccomp-gated: it needs CAP_NET_ADMIN (netns +
//! netkit + nft), KVM, and the guest image at /var/lib/aurae/vm/.

use client::cells::cell_service::CellServiceClient;
use client::discovery::discovery_service::DiscoveryServiceClient;
use client::vms::vm_service::VmServiceClient;
use client::{Client, ClientError};
use common::cells::CellServiceAllocateRequestBuilder;
use common::remote_auraed_client;
use proto::cells::CellServiceFreeRequest;
use proto::discovery::DiscoverRequest;
use proto::vms::{
    RootDrive, VirtualMachine, VmServiceAllocateRequest, VmServiceFreeRequest,
    VmServiceStartRequest,
};
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
#[ignore]
async fn vm_in_cell_is_hosted_by_nested_auraed_and_reachable_from_host() {
    skip_if_not_root!("vm_in_cell_is_hosted_by_nested_auraed");
    skip_if_seccomp!("vm_in_cell_is_hosted_by_nested_auraed");

    let client = common::auraed_client().await;

    // 1. Allocate an isolated cell. isolate_network=true is what gives the
    //    nested auraed a delegated /112 prefix and a seeded Network/IPAM, so
    //    it can host VMs of its own.
    let cell_name = retry!(
        CellServiceClient::allocate(
            &client,
            CellServiceAllocateRequestBuilder::new().isolate_network().build()
        )
        .await
    )
    .expect("allocate isolated cell")
    .into_inner()
    .cell_name;

    // 2. Allocate + start a VM through the proxy. The host forwards both RPCs
    //    into the cell's nested auraed, which hosts the VM locally.
    let vm_id = format!("ae-test-vm-{}", uuid::Uuid::new_v4());
    retry!(
        VmServiceClient::allocate(
            &client,
            VmServiceAllocateRequest {
                machine: Some(VirtualMachine {
                    id: vm_id.clone(),
                    mem_size_mb: 1024,
                    vcpu_count: 2,
                    kernel_img_path: "/var/lib/aurae/vm/kernel/vmlinux.bin"
                        .to_string(),
                    kernel_args: vec![
                        "console=hvc0".to_string(),
                        "root=/dev/vda1".to_string(),
                        "rw".to_string(),
                    ],
                    root_drive: Some(RootDrive {
                        image_path: "/var/lib/aurae/vm/image/disk.raw".into(),
                        read_only: false,
                    }),
                    drive_mounts: vec![],
                    auraed_address: String::new(),
                }),
                cell_name: Some(cell_name.clone()),
            }
        )
        .await
    )
    .expect("proxied VmService.allocate should succeed inside the cell");

    let started = VmServiceClient::start(
        &client,
        VmServiceStartRequest {
            vm_id: vm_id.clone(),
            cell_name: Some(cell_name.clone()),
        },
    )
    .await
    .expect("proxied VmService.start should succeed")
    .into_inner();

    // The address is the VM's guest ULA inside the cell's /112 — routable
    // from the host via the cell's netkit primary.
    assert!(
        started.auraed_address.starts_with("[fd00:ae:"),
        "expected an in-pool guest address, got {:?}",
        started.auraed_address
    );

    // 3. From the *host*, reach the guest auraed. Success proves the full
    //    host → netkit → cell netns → TAP → guest path works end to end.
    let mut remote_client: Result<Client, ClientError> =
        remote_auraed_client(started.auraed_address.clone()).await;
    for _ in 0..10 {
        if remote_client.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        remote_client =
            remote_auraed_client(started.auraed_address.clone()).await;
    }
    let remote_client =
        remote_client.expect("could not reach the in-cell VM's guest auraed");

    let discovered = remote_client
        .discover(DiscoverRequest {})
        .await
        .expect("guest auraed Discover failed")
        .into_inner();
    assert!(discovered.healthy, "guest auraed reported unhealthy");

    // 4. Cleanup: free the VM through the proxy, then free the cell.
    let _ = VmServiceClient::free(
        &client,
        VmServiceFreeRequest {
            vm_id: vm_id.clone(),
            cell_name: Some(cell_name.clone()),
        },
    )
    .await;
    let _ =
        CellServiceClient::free(&client, CellServiceFreeRequest { cell_name })
            .await;
}
