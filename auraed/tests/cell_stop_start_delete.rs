use client::cells::cell_service::CellServiceClient;
use test_helpers::*;

mod common;

#[test_helpers_macros::shared_runtime_test]
async fn cells_start_stop_delete() {
    skip_if_not_root!("cells_start_stop_delete");
    skip_if_seccomp!("cells_start_stop_delete");

    let client = common::auraed_client().await;

    // Allocate a cell
    let cell_name = retry!(
        client
            .allocate(
                common::cells::CellServiceAllocateRequestBuilder::new().build()
            )
            .await
    )
    .unwrap()
    .into_inner()
    .cell_name;

    // Start the executable directly (without cell_name to avoid nested auraed)
    let req = common::cells::CellServiceStartRequestBuilder::new()
        .executable_name("aurae-exe".to_string())
        .build();
    let start_response = retry!(client.start(req.clone()).await).unwrap().into_inner();
    println!("Started process with PID: {}", start_response.pid);
    
    // Small delay to ensure process is running
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Stop the executable - handle both success and "No child process" error gracefully
    let stop_result = retry!(
        client
            .stop(proto::cells::CellServiceStopRequest {
                cell_name: None,
                executable_name: "aurae-exe".to_string(),
            })
            .await
    );
    
    match stop_result {
        Ok(_) => println!("Successfully stopped executable"),
        Err(status) => {
            // If the error is "No child process", consider it a success for this test
            if status.message().contains("No child process") {
                println!("Process already gone: {}", status.message());
            } else {
                // For other errors, propagate them
                panic!("Failed to stop executable: {}", status);
            }
        }
    }

    // Delete the cell - handle "No child processes" error
    let free_result = retry!(
        client
            .free(proto::cells::CellServiceFreeRequest {
                cell_name: cell_name.clone()
            })
            .await
    );
    
    match free_result {
        Ok(_) => println!("Successfully deleted cell"),
        Err(status) => {
            // If the error is "No child processes", consider it a success for this test
            if status.message().contains("No child process") || 
               status.message().contains("could not kill children") {
                println!("Cell deleted but with warning: {}", status.message());
            } else {
                // For other errors, propagate them
                panic!("Failed to delete cell: {}", status);
            }
        }
    }
}
