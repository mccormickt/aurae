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

//! A `cell_name`-scoped `VmService` request reaches the nested auraed of the
//! cell with the VM control capability. The nested auraed refuses each
//! `VmService` request without it. `List` needs no KVM, thus this test runs
//! on a host without VM support.

use client::cells::cell_service::CellServiceClient;
use client::vms::vm_service::VmServiceClient;
use common::cells::CellServiceAllocateRequestBuilder;
use proto::cells::CellServiceFreeRequest;
use proto::vms::VmServiceListRequest;
use test_helpers::*;
use tonic::Code;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn vms_list_must_proxy_into_cell() {
    skip_if_not_root!("vms_list_must_proxy_into_cell");
    skip_if_seccomp!("vms_list_must_proxy_into_cell");

    let client = common::auraed_client().await;

    let cell_name = retry!(
        CellServiceClient::allocate(
            &client,
            CellServiceAllocateRequestBuilder::new().build()
        )
        .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    let machines = retry!(
        VmServiceClient::list(
            &client,
            VmServiceListRequest { cell_name: Some(cell_name.clone()) }
        )
        .await
    )
    .expect("proxied VmService.list must reach the nested auraed")
    .into_inner()
    .machines;
    assert!(machines.is_empty(), "a new cell hosts no VM: {machines:?}");

    let missing = VmServiceClient::list(
        &client,
        VmServiceListRequest { cell_name: Some("no-such-cell".to_string()) },
    )
    .await
    .expect_err("an unknown cell must not be served");
    assert_eq!(missing.code(), Code::NotFound, "{missing:?}");

    let _ =
        CellServiceClient::free(&client, CellServiceFreeRequest { cell_name })
            .await;
}
